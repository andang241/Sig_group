import requests
import json
import pandas as pd
from getpass import getpass
import warnings
from typing import Dict, List, Any, Generator, Set, Tuple
from difflib import SequenceMatcher
import random
import re
from datetime import datetime, timedelta
from collections import defaultdict
import gc
import hashlib

# --- CONFIGURATION ---

# 1. Thông tin kết nối Wazuh Indexer
INDEXER_DOMAIN = "https://wazuh-indexer.misaonline.vpnlocal"
INDEXER_USER = 'dban'

# 2. Danh sách các Rule ID bạn muốn theo dõi
RULES_TO_MONITOR = [
    "142749"
]

# 3. Streaming configuration - Cấu hình xử lý dữ liệu theo chunks
CHUNK_SIZE = 5000                    # Số events xử lý mỗi lần
MAX_GROUPS_IN_MEMORY = 15000         # Giới hạn số groups trong memory
MEMORY_CLEANUP_INTERVAL = 50000      # Tần suất cleanup memory

# 4. Enhanced deduplication configuration - Cấu hình dedup cho từng loại event
DEDUP_CONFIG_BY_GROUP_ENHANCED = {
    "sigmaprocess_creation": {
        "event_type": "sigmaprocess_creation",
        "primary_fields": [                    # Các trường CHÍNH để nhóm events
            "data.win.eventdata.parentImage", # Process cha (ví dụ: forfiles.exe)
            "data.win.eventdata.user"         # User thực thi (ví dụ: NT AUTHORITY\SYSTEM)
        ],
        "similarity_fields": [                # Các trường để so sánh similarity
            "data.win.eventdata.commandLine",      # Command line
            "data.win.eventdata.parentCommandLine" # Parent command line
        ],
        "max_samples_per_group": 10,         # Số events tối đa trong 1 group
        "similarity_threshold": 0.75,        # Ngưỡng similarity để nhóm (75%)
        "use_enhanced_similarity": True,     # Sử dụng enhanced similarity
        "time_window_minutes": 120,          # Time window để nhóm (2 giờ)
        "use_semantic_similarity": True      # Sử dụng semantic similarity
    },
    "network_connection": {
        "event_type": "network_connection",
        "primary_fields": [
            "data.win.eventdata.image",
            "data.win.eventdata.protocol"
        ],
        "similarity_fields": [
            "data.win.eventdata.destinationIp",
            "data.win.eventdata.destinationPort",
            "data.win.eventdata.destinationHostname"
        ],
        "max_samples_per_group": 5,
        "similarity_threshold": 0.80,  # Reduced from 0.90
        "use_enhanced_similarity": False,
        "time_window_minutes": 60,  # Increased from 30
        "use_semantic_similarity": False
    },
    "file_event": {
        "event_type": "file_event",
        "primary_fields": [
            "data.win.eventdata.image"
        ],
        "similarity_fields": [
            "data.win.eventdata.targetFilename",
            "data.win.eventdata.image"              
        ],
        "max_samples_per_group": 8,  # Increased from 5
        "similarity_threshold": 0.85,  # Reduced from 0.85
        "use_enhanced_similarity": True,
        "time_window_minutes": 90,  # Increased from 45
        "use_semantic_similarity": True
    },
    "registry_set": {
        "event_type": "registry_set",
        "primary_fields": [
            "data.win.eventdata.image",
            "data.win.eventdata.eventType"
        ],
        "similarity_fields": [
            "data.win.eventdata.targetObject"
        ],
        "max_samples_per_group": 5,
        "similarity_threshold": 0.75,  # Reduced from 0.85
        "use_enhanced_similarity": False,
        "time_window_minutes": 60,  # Increased from 30
        "use_semantic_similarity": False
    },
    "default": {
        "event_type": "generic",
        "primary_fields": ["rule.id", "rule.level", "agent.name"],
        "similarity_fields": ["full_log"],
        "max_samples_per_group": 8,  # Increased from 5
        "similarity_threshold": 0.75,  # Reduced from 0.95 for better grouping
        "use_enhanced_similarity": True,
        "time_window_minutes": 120,  # Increased from 60
        "use_semantic_similarity": True
    }
}

# 5. Các cấu hình khác
FETCH_SIZE_PER_PAGE = CHUNK_SIZE
TIME_RANGE = "now-1d"  # UTC+7 (Giờ Việt Nam) - Lấy dữ liệu 1 ngày trước theo giờ Việt Nam
# Giải thích: 
# - now: Thời điểm hiện tại
# - -1d: Trừ đi 1 ngày  
# - /d: Làm tròn xuống đến đầu ngày (00:00:00)
# - +07:00: Chuyển về UTC+7 (Giờ Việt Nam)
# Ví dụ: Nếu bây giờ là 18/08/2025 22:30 (giờ Việt Nam)
# → Script sẽ query từ 17/08/2025 00:00 (giờ Việt Nam) đến hiện tại
USER_AGENT = 'curl/7.81.0'
MAX_EVENTS_TO_PROCESS = 2000000

# Tắt cảnh báo SSL
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)


# --- UTILITY FUNCTIONS ---

def get_nested_value(obj: Dict, path: str) -> Any:
    """
    Lấy giá trị nested từ dictionary theo đường dẫn dạng 'data.win.eventdata.parentImage'
    
    Args:
        obj: Dictionary chứa dữ liệu
        path: Đường dẫn dạng 'field1.field2.field3'
    
    Returns:
        Giá trị tại đường dẫn hoặc None nếu không tìm thấy
    
    Ví dụ:
        get_nested_value(event, 'data.win.eventdata.parentImage')
        → Trả về 'C:\\Windows\\System32\\forfiles.exe'
    """
    keys = path.split('.')
    current = obj
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else: 
            return None
    return current

def safe_str(value: Any) -> str:
    """
    Chuyển đổi an toàn sang string, tránh lỗi khi value là None
    
    Args:
        value: Giá trị cần chuyển đổi
    
    Returns:
        String representation của value, hoặc "" nếu value là None
    """
    if value is None:
        return ""
    return str(value)


# --- ENHANCED SIMILARITY FUNCTIONS ---

def normalize_command_line_enhanced(cmd_line: str) -> str:
    """
    Chuẩn hóa command line để so sánh similarity chính xác hơn
    
    Mục đích: Loại bỏ các thông tin không cần thiết (GUIDs, timestamps, đường dẫn cụ thể)
    để giữ lại cấu trúc và logic của command.
    
    Args:
        cmd_line: Command line gốc
    
    Returns:
        Command line đã được chuẩn hóa
    
    Ví dụ:
        Input:  'forfiles /p "C:\\temp" /s /d -3 /c "cmd /c del \"Bang_ke_1755415510625.xls\" /q"'
        Output: 'forfiles /p QUOTED_PATH /s /d -3 /c "cmd /c del \\QUOTED_PATH /q"'
    """
    if not cmd_line:
        return ""
    
    try:
        cmd = cmd_line.lower().strip()
        
        # 1. Normalize conditional statements - Chuẩn hóa các câu lệnh điều kiện
        cmd = re.sub(r'if\s+(true|false)==(true|false)', 'if CONDITION', cmd)
        cmd = re.sub(r'if\s+/i\s+not', 'if not', cmd)
        
        # 2. Replace ALL GUIDs with consistent pattern - Thay thế GUIDs bằng pattern nhất quán
        cmd = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'GUID', cmd)
        
        # 3. Normalize file extensions and paths - Chuẩn hóa extensions và đường dẫn
        cmd = re.sub(r'_\d{8}_\d{6,}', '_TIMESTAMP', cmd)  # file timestamps
        cmd = re.sub(r'_\d{8}\.', '_DATE.', cmd)  # date patterns
        cmd = re.sub(r'\d{2}\.\d{2}\.\d{4}', 'DATE', cmd)  # DD.MM.YYYY
        cmd = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', cmd)    # YYYY-MM-DD
        
        # 4. Replace specific Vietnamese file patterns - Thay thế pattern file tiếng Việt
        cmd = re.sub(r'"[^"]*\.(xlsx?|docx?|pdf|txt|log)"', 'DOCUMENT', cmd)
        cmd = re.sub(r'"[^"]*_\d+\.(xlsx?|docx?|pdf)"', 'DOCUMENT', cmd)
        
        # 5. Normalize numbers and IDs - Chuẩn hóa số và IDs
        cmd = re.sub(r'\b\d{8,}\b', 'LONGID', cmd)  # Long numeric IDs
        cmd = re.sub(r'\b\d{5,7}\b', 'MEDIUMID', cmd)  # Medium IDs
        
        # 6. Normalize Vietnamese document names patterns - Chuẩn hóa tên tài liệu tiếng Việt
        cmd = re.sub(r'"[^"]*thang\s+\d+[^"]*"', 'MONTHLY_REPORT', cmd)
        cmd = re.sub(r'"[^"]*chi_tiet[^"]*"', 'DETAIL_REPORT', cmd)
        cmd = re.sub(r'"[^"]*bang_ke[^"]*"', 'SUMMARY_REPORT', cmd)
        
        # 7. Replace quoted file paths entirely - Thay thế toàn bộ đường dẫn trong dấu ngoặc kép
        cmd = re.sub(r'"[^"]*"', 'QUOTED_PATH', cmd)
        
        # 8. Normalize drives and common paths - Chuẩn hóa ổ đĩa và đường dẫn chung
        cmd = re.sub(r'[c-z]:\\[^\s]*', 'FILEPATH', cmd)
        
        # 9. Clean up multiple spaces - Dọn dẹp khoảng trắng thừa
        cmd = ' '.join(cmd.split())
        
        return cmd
        
    except Exception as e:
        print(f"Warning: Lỗi normalize_command_line_enhanced: {e}")
        return cmd_line.lower().strip()

def normalize_command_line(cmd_line: str) -> str:
    """Wrapper function - sử dụng enhanced version"""
    return normalize_command_line_enhanced(cmd_line)

def extract_command_tokens(cmd_line: str) -> Set[str]:
    """
    Trích xuất các token quan trọng từ command line để tính Jaccard similarity
    
    Args:
        cmd_line: Command line cần trích xuất tokens
    
    Returns:
        Set các tokens có ý nghĩa (loại bỏ stop words)
    
    Ví dụ:
        Input:  'cmd /c del /q "C:\\temp\\file.txt"'
        Output: {'cmd', 'del', 'temp', 'file', 'txt'}
    """
    if not cmd_line:
        return set()
    
    # Tách thành tokens
    tokens = re.findall(r'[\w\-\.]+', cmd_line.lower())
    
    # Loại bỏ tokens không quan trọng
    ignore_tokens = {'exe', 'dll', 'com', 'bat', 'ps1', 'vbs', 'js', 'the', 'and', 'or', 'to', 'in', 'of', 'is', 'it'}
    meaningful_tokens = {token for token in tokens if len(token) > 2 and token not in ignore_tokens}
    
    return meaningful_tokens

def extract_command_structure(cmd_line: str) -> str:
    """
    Trích xuất cấu trúc lệnh cốt lõi (loại bỏ các giá trị cụ thể)
    
    Args:
        cmd_line: Command line gốc
    
    Returns:
        Cấu trúc command đã được chuẩn hóa
    
    Ví dụ:
        Input:  'forfiles /p "C:\\temp" /s /d -3 /c "cmd /c del @file /q"'
        Output: 'forfiles /p FILEPATH /s /d -3 /c "cmd /c del @file /q"'
    """
    if not cmd_line:
        return ""
    
    structure = cmd_line.lower()
    
    # Thay thế toàn bộ đường dẫn bằng PATH placeholder
    structure = re.sub(r'"[c-z]:\\[^"]*"', 'FILEPATH', structure)
    structure = re.sub(r'[c-z]:\\[^\s]*', 'FILEPATH', structure)
    
    # Thay thế parameters với values
    structure = re.sub(r'-\w+\s+[^\s-]+', 'PARAM VALUE', structure)
    
    return structure.strip()

def extract_command_pattern_enhanced(cmd_line: str) -> str:
    """
    Phát hiện pattern của command để nhóm các commands tương tự
    
    Mục đích: Phân loại commands theo mục đích sử dụng (file deletion, cleanup, etc.)
    
    Args:
        cmd_line: Command line cần phân loại
    
    Returns:
        Pattern string mô tả loại command
    
    Ví dụ:
        'forfiles /p C:\temp /s /d -3 /c "cmd /c del @file /q"' → 'forfiles_scheduled_cleanup'
        'cmd /c del /q file.txt' → 'quiet_file_deletion'
    """
    if not cmd_line:
        return "empty"
    
    cmd = cmd_line.lower().strip()
    
    # Special handling for forfiles.exe patterns - Xử lý đặc biệt cho forfiles.exe
    if "forfiles" in cmd:
        if "del" in cmd and "/d -" in cmd:
            return "forfiles_scheduled_cleanup"  # forfiles with date-based deletion
        elif "del" in cmd:
            return "forfiles_file_deletion"      # forfiles with deletion
        else:
            return "forfiles_generic"            # other forfiles usage
    
    # Specific business patterns first - Các pattern nghiệp vụ cụ thể
    if "if true==false" in cmd or "if false==false" in cmd:
        if "del" in cmd:
            return "conditional_delete_safe"  # Safe delete (never executes)
        elif "if /i not" in cmd:
            return "conditional_file_check_safe"  # Safe file existence check
    
    # General patterns - Các pattern chung
    if "cmd /c" in cmd and "del" in cmd and "/q" in cmd:
        return "silent_file_delete"
    elif "powershell" in cmd:
        if "invoke-webrequest" in cmd or "downloadstring" in cmd:
            return "powershell_download"
        elif "-enc" in cmd:
            return "powershell_encoded"
        else:
            return "powershell_generic"
    elif "rundll32" in cmd:
        return "rundll32_execution"
    elif "tasklist" in cmd:
        return "process_enumeration"
    elif "net user" in cmd:
        return "user_management"
    elif "reg add" in cmd or "reg delete" in cmd:
        return "registry_modification"
    elif "del" in cmd and "/q" in cmd:
        return "quiet_file_deletion"
    elif "del" in cmd:
        return "file_deletion"
    else:
        return "generic"

def extract_command_pattern(cmd_line: str) -> str:
    """Wrapper function - sử dụng enhanced version"""
    return extract_command_pattern_enhanced(cmd_line)

def calculate_jaccard_similarity(set1: Set, set2: Set) -> float:
    """
    Tính Jaccard similarity coefficient giữa 2 sets
    
    Công thức: J(A,B) = |A ∩ B| / |A ∪ B|
    
    Args:
        set1: Set thứ nhất
        set2: Set thứ hai
    
    Returns:
        Giá trị similarity từ 0.0 đến 1.0
    
    Ví dụ:
        set1 = {'cmd', 'del', 'file'}
        set2 = {'cmd', 'del', 'temp'}
        → Jaccard = 2/4 = 0.5
    """
    if not set1 and not set2:
        return 1.0
    if not set1 or not set2:
        return 0.0
    
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0

def calculate_semantic_similarity(str1: str, str2: str) -> float:
    """
    Tính semantic similarity nâng cao cho Vietnamese file names
    
    Mục đích: So sánh ý nghĩa thực sự của commands, không chỉ text matching
    
    Args:
        str1: String thứ nhất
        str2: String thứ hai
    
    Returns:
        Giá trị similarity từ 0.0 đến 1.0
    """
    if not str1 or not str2:
        return 0.0
    
    # Normalize both strings
    norm1 = normalize_command_line_enhanced(str1)
    norm2 = normalize_command_line_enhanced(str2)
    
    # Exact match after normalization
    if norm1 == norm2:
        return 1.0
    
    # Pattern-based similarity
    pattern1 = extract_command_pattern_enhanced(str1)
    pattern2 = extract_command_pattern_enhanced(str2)
    
    if pattern1 == pattern2:
        # Same pattern, check structural similarity
        return SequenceMatcher(None, norm1, norm2).ratio()
    else:
        # Different patterns
        return 0.0

def calculate_enhanced_similarity(str1: str, str2: str) -> float:
    """
    Tính similarity bằng cách kết hợp nhiều phương pháp
    
    Strategy: Kết hợp pattern matching, structural similarity, normalized similarity, và token-based similarity
    
    Args:
        str1: String thứ nhất
        str2: String thứ hai
    
    Returns:
        Giá trị similarity từ 0.0 đến 1.0
    """
    if not str1 or not str2:
        return 0.0
    
    try:
        # 1. Command pattern matching (highest priority - 35%)
        pattern1 = extract_command_pattern_enhanced(str1)
        pattern2 = extract_command_pattern_enhanced(str2)
        pattern_sim = 1.0 if pattern1 == pattern2 else 0.0
        
        # Nếu patterns khác nhau hoàn toàn, similarity thấp
        if pattern_sim == 0.0 and pattern1 != "generic" and pattern2 != "generic":
            return 0.0
        
        # 2. Structural similarity (25%)
        struct1 = extract_command_structure(str1)
        struct2 = extract_command_structure(str2)
        struct_sim = SequenceMatcher(None, struct1, struct2).ratio()
        
        # 3. Normalized similarity (25%)
        norm_str1 = normalize_command_line_enhanced(str1)
        norm_str2 = normalize_command_line_enhanced(str2)
        norm_sim = SequenceMatcher(None, norm_str1, norm_str2).ratio()
        
        # 4. Token-based similarity (15%)
        tokens1 = extract_command_tokens(norm_str1)
        tokens2 = extract_command_tokens(norm_str2)
        jaccard_sim = calculate_jaccard_similarity(tokens1, tokens2)
        
        # Weighted combination - Kết hợp có trọng số
        final_similarity = (pattern_sim * 0.35 + struct_sim * 0.25 + norm_sim * 0.25 + jaccard_sim * 0.15)
        
        return final_similarity
        
    except Exception as e:
        print(f"Warning: Lỗi calculate_enhanced_similarity: {e}")
        return 0.0

def calculate_standard_similarity(str1: str, str2: str) -> float:
    """
    Similarity calculation chuẩn (faster) - Sử dụng SequenceMatcher đơn giản
    
    Args:
        str1: String thứ nhất
        str2: String thứ hai
    
    Returns:
        Giá trị similarity từ 0.0 đến 1.0
    """
    if not str1 or not str2:
        return 0.0
    
    # Normalize và dùng SequenceMatcher
    norm_str1 = normalize_command_line_enhanced(str1)
    norm_str2 = normalize_command_line_enhanced(str2)
    
    return SequenceMatcher(None, norm_str1, norm_str2).ratio()


# --- RULE GROUP FUNCTIONS ---

def get_rule_groups_from_event(event: Dict) -> List[str]:
    """
    Lấy rule groups từ event để xác định loại event
    
    Args:
        event: Event dictionary từ Wazuh
    
    Returns:
        List các rule groups (ví dụ: ['process_creation', 'windows'])
    
    Ví dụ:
        event['rule']['groups'] = ['process_creation', 'windows', 'file_operation']
        → Returns: ['process_creation', 'windows', 'file_operation']
    """
    return event.get('rule', {}).get('groups', [])

def determine_dedup_config(event: Dict) -> Dict:
    """
    Xác định config dedup dựa trên rule groups của event
    
    Mục đích: Mỗi loại event (process_creation, network_connection, etc.) 
    có config dedup riêng phù hợp với đặc điểm của nó.
    
    Args:
        event: Event dictionary từ Wazuh
    
    Returns:
        Config dedup phù hợp cho loại event này
    
    Ví dụ:
        - process_creation → DEDUP_CONFIG_BY_GROUP_ENHANCED["process_creation"]
        - network_connection → DEDUP_CONFIG_BY_GROUP_ENHANCED["network_connection"]
        - Không match → DEDUP_CONFIG_BY_GROUP_ENHANCED["default"]
    """
    # Debug: In ra thông tin event để kiểm tra
    # print(f"\n🔍 DEBUG - Event info:")
    # print(f"  • Rule ID: {get_nested_value(event, 'rule.id')}")
    # print(f"  • Rule Description: {get_nested_value(event, 'rule.description')}")
    # print(f"  • Image: {get_nested_value(event, 'data.win.eventdata.image')}")
    # print(f"  • User: {get_nested_value(event, 'data.win.eventdata.user')}")
    # print(f"  • ParentImage: {get_nested_value(event, 'data.win.eventdata.parentImage')}")
    
    rule_groups = get_rule_groups_from_event(event)
    print(f"  • Rule Groups: {rule_groups}")
    
    # Priority order cho việc matching groups
    group_priority = ['sigmaprocess_creation', 'network_connection', 'registry_set', 'file_event']
    
    for priority_group in group_priority:
        if priority_group in rule_groups:
            config = DEDUP_CONFIG_BY_GROUP_ENHANCED.get(priority_group, DEDUP_CONFIG_BY_GROUP_ENHANCED["default"])
            print(f"  • ✅ Using config: {priority_group}")
            print(f"  • Primary fields: {config.get('primary_fields', [])}")
            return config
    
    # Fallback to default
    config = DEDUP_CONFIG_BY_GROUP_ENHANCED["default"]
    print(f"  • ⚠️ Using default config")
    print(f"  • Primary fields: {config.get('primary_fields', [])}")
    return config


# --- TIME-BASED GROUPING ---

def group_events_by_time(events: List[Dict], time_window_minutes: int = 30) -> Dict[str, List[Dict]]:
    """
    Nhóm events theo time windows để xử lý hiệu quả hơn
    
    Mục đích: 
    1. Giảm memory usage bằng cách xử lý theo chunks thời gian
    2. Nhóm events gần nhau về thời gian (có thể liên quan đến nhau)
    3. Tránh so sánh events cách xa nhau về thời gian
    
    Args:
        events: List các events cần nhóm
        time_window_minutes: Khoảng thời gian mỗi window (phút)
    
    Returns:
        Dictionary với key là time window, value là list events trong window đó
    
    Ví dụ:
        time_window_minutes = 60
        → Events từ 18:00-19:00 → "2025-08-17_18:00"
        → Events từ 19:00-20:00 → "2025-08-17_19:00"
    """
    time_groups = defaultdict(list)
    
    for event in events:
        timestamp_str = event.get('@timestamp')
        if not timestamp_str:
            time_groups['no_timestamp'].append(event)
            continue
            
        try:
            # Parse timestamp
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            
            # Làm tròn về time window
            minutes_rounded = (dt.minute // time_window_minutes) * time_window_minutes
            rounded_time = dt.replace(minute=minutes_rounded, second=0, microsecond=0)
            
            time_key = rounded_time.strftime('%Y-%m-%d_%H:%M')
            time_groups[time_key].append(event)
            
        except Exception as e:
            time_groups['invalid_timestamp'].append(event)
    
    return dict(time_groups)


# --- ENHANCED GROUP KEY GENERATION ---

def create_enhanced_group_key(event: Dict, config: Dict) -> str:
    """
    Tạo group key với PRIORITY cho primary fields, commandLine chỉ để refine
    
    Strategy: 
    1. PRIMARY FIELDS FIRST: parentImage + user (ví dụ: forfiles.exe + NT AUTHORITY\SYSTEM)
    2. COMMAND PATTERN SECONDARY: Chỉ để organize trong primary group
    
    Args:
        event: Event dictionary từ Wazuh
        config: Config dedup cho loại event này
    
    Returns:
        Group key string dạng "hash_pattern"
    
    Ví dụ:
        - parentImage: "C:\\Windows\\System32\\forfiles.exe"
        - user: "NT AUTHORITY\\SYSTEM"
        - pattern: "forfiles_scheduled_cleanup"
        → Returns: "a1b2c3d4_forfiles_scheduled_cleanup"
    """
    primary_fields = config.get("primary_fields", [])
    
    # PRIORITY 1: Primary fields (parentImage, user, etc.) - MUST MATCH
    base_parts = []
    for field in primary_fields:
        value = safe_str(get_nested_value(event, field))
        if not value:  # If primary field is missing, use placeholder
            value = "MISSING"
        base_parts.append(value)
    
    # Debug: In ra primary fields values
    # print(f"  🔑 DEBUG - Primary fields values:")
    # for i, field in enumerate(primary_fields):
    #     print(f"    • {field}: '{base_parts[i]}'")
    
    # PRIORITY 2: Command pattern (only for refinement, not primary grouping)
    cmd_line = safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
    pattern = extract_command_pattern_enhanced(cmd_line)
    
    # Create hash for consistent grouping - PRIMARY FIELDS FIRST
    group_str = "|".join(base_parts)  # Only primary fields for main grouping
    group_hash = hashlib.md5(group_str.encode()).hexdigest()[:8]
    
    final_key = f"{group_hash}_{pattern}"
    print(f"    • Group string: {group_str}")
    print(f"    • Group hash: {group_hash}")
    print(f"    • Pattern: {pattern}")
    print(f"    • Final key: {final_key}")
    
    # Pattern is secondary - only used for internal organization
    return final_key


# --- ENHANCED STREAMING DEDUPLICATION CLASS ---

class StreamingDeduplicatorV2:
    """
    Class chính xử lý deduplication streaming với memory management
    
    Mục đích: 
    1. Xử lý events theo chunks để tiết kiệm memory
    2. Merge các groups từ chunks khác nhau
    3. Cleanup memory định kỳ để tránh memory overflow
    4. Tạo final results với metadata đầy đủ
    
    Attributes:
        config: Config dedup cho loại event
        global_groups: Dictionary chứa tất cả groups đã xử lý
        processed_count: Số events đã xử lý
    """
    
    def __init__(self, config: Dict):
        """
        Khởi tạo deduplicator với config
        
        Args:
            config: Config dedup từ DEDUP_CONFIG_BY_GROUP_ENHANCED
        """
        self.config = config
        self.global_groups = {}  # Lưu trữ tất cả groups
        self.processed_count = 0 # Đếm số events đã xử lý
        
    def merge_groups_into_global(self, chunk_groups: List[Dict]) -> None:
        """
        Merge các groups từ chunk hiện tại vào global groups
        
        Mục đích: Tích lũy thông tin từ các chunks khác nhau để có cái nhìn tổng quan
        
        Args:
            chunk_groups: List các events đã được dedup trong chunk hiện tại
        """
        # print(f"\n🔄 DEBUG - Merging {len(chunk_groups)} groups into global")
        
        for event in chunk_groups:
            group_info = event.get('_group_info', {})
            pattern = group_info.get('pattern', 'unknown')
            primary_key = group_info.get('primary_key', 'unknown')  # Lấy primary key
            
            # Create semantic key for global grouping
            cmd_line = safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
            normalized_cmd = normalize_command_line_enhanced(cmd_line)
            
            # Tạo key duy nhất cho global group - SỬ DỤNG PRIMARY KEY + PATTERN
            global_key = f"{primary_key}:{pattern}"
            
            print(f"  • Processing: {primary_key} | {pattern}")
            print(f"    - Global key: {global_key}")
            print(f"    - Events in group: {group_info.get('total_events_in_group', 1)}")
            
            if global_key in self.global_groups:
                # Merge vào existing group
                old_total = self.global_groups[global_key]['total_events']
                self.global_groups[global_key]['total_events'] += group_info.get('total_events_in_group', 1)
                print(f"    - ✅ Merged into existing group: {old_total} → {self.global_groups[global_key]['total_events']} events")
            else:
                # Tạo global group mới
                self.global_groups[global_key] = {
                    'representative': event,
                    'total_events': group_info.get('total_events_in_group', 1),
                    'first_seen': group_info.get('first_seen', ''),
                    'last_seen': group_info.get('last_seen', ''),
                    'pattern': pattern,
                    'primary_key': primary_key,  # Thêm primary key vào global group
                    'normalized_command': normalized_cmd,
                    'risk_score': event.get('_risk_score', {})
                }
                print(f"    - 🆕 Created new global group")
        
        print(f"  • Total global groups after merge: {len(self.global_groups)}")
    
    def should_merge_groups(self, event1: Dict, event2: Dict) -> bool:
        """
        Kiểm tra nhanh xem 2 events có nên ở cùng global group không
        
        Args:
            event1: Event thứ nhất
            event2: Event thứ hai
        
        Returns:
            True nếu nên merge, False nếu không
        """
        similarity_fields = self.config.get("similarity_fields", [])
        similarity_threshold = self.config.get("similarity_threshold", 0.75)
        use_semantic = self.config.get("use_semantic_similarity", False)
        
        # Chọn function similarity phù hợp
        if use_semantic:
            similarity_func = calculate_semantic_similarity
        else:
            similarity_func = calculate_enhanced_similarity if self.config.get("use_enhanced_similarity") else calculate_standard_similarity
        
        # So sánh similarity cho tất cả similarity fields
        for field in similarity_fields:
            val1 = safe_str(get_nested_value(event1, field))
            val2 = safe_str(get_nested_value(event2, field))
            
            if val1 and val2:
                sim = similarity_func(val1, val2)
                if sim >= similarity_threshold:
                    return True
        
        return False
    
    def cleanup_memory(self) -> None:
        """
        Cleanup memory để tránh memory overflow
        
        Strategy: Giữ lại các groups có nhiều events nhất từ mỗi pattern
        """
        if len(self.global_groups) <= MAX_GROUPS_IN_MEMORY:
            return
        
        print(f"🧹 Memory cleanup - Groups: {len(self.global_groups)}")
        
        # Group by pattern first để preserve diversity
        pattern_groups = defaultdict(list)
        for key, data in self.global_groups.items():
            pattern = data.get('pattern', 'unknown')
            pattern_groups[pattern].append((key, data))
        
        # Keep top groups from each pattern
        new_groups = {}
        max_per_pattern = max(1, MAX_GROUPS_IN_MEMORY // len(pattern_groups))
        
        for pattern, groups in pattern_groups.items():
            # Sort by total_events và keep top ones
            sorted_groups = sorted(groups, key=lambda x: x[1]['total_events'], reverse=True)
            for key, data in sorted_groups[:max_per_pattern]:
                new_groups[key] = data
        
        removed = len(self.global_groups) - len(new_groups)
        self.global_groups = new_groups
        
        print(f"   Removed {removed} groups, kept {len(new_groups)} across {len(pattern_groups)} patterns")
        gc.collect()  # Force garbage collection
    
    def get_final_results(self) -> List[Dict]:
        """
        Convert global groups thành final results với metadata đầy đủ
        
        Returns:
            List các events representative với group info và risk score
        """
        # print(f"\n📊 DEBUG - Converting {len(self.global_groups)} global groups to final results")
        
        results = []
        for global_key, group_data in self.global_groups.items():
            representative = group_data['representative'].copy()
            
            # Update group info với thông tin từ global group
            representative['_group_info'].update({
                'total_events_in_group': group_data['total_events'],
                'first_seen': group_data['first_seen'],
                'last_seen': group_data['last_seen'],
                'pattern': group_data['pattern'],
                'primary_key': group_data.get('primary_key', 'unknown'),
                'normalized_command': group_data['normalized_command'],
                'risk_score': group_data['risk_score']
            })
            
            print(f"  • {global_key}: {group_data['total_events']} events")
            results.append(representative)
        
        print(f"  • Total final results: {len(results)}")
        return results


# --- ENHANCED MAIN DEDUPLICATION FUNCTION ---

def advanced_similarity_dedup_v2(events: List[Dict], config: Dict) -> List[Dict]:
    """
    Enhanced deduplication với PRIORITY cho primary fields, commandLine chỉ để refine
    
    Strategy:
    1. STEP 1: Group by PRIMARY FIELDS (parentImage, user, etc.) trước
    2. STEP 2: Trong mỗi primary group, apply commandLine similarity refinement
    
    Mục đích: 
    - Tránh over-grouping (tạo quá nhiều groups nhỏ)
    - Ưu tiên grouping theo process và user thay vì command line
    - Chỉ sử dụng command line để refine trong primary groups
    
    Args:
        events: List các events cần dedup
        config: Config dedup từ DEDUP_CONFIG_BY_GROUP_ENHANCED
    
    Returns:
        List các events representative (đã dedup)
    
    Ví dụ:
        Input: 300k events của forfiles.exe + NT AUTHORITY\SYSTEM
        Step 1: Tất cả → 1 primary group
        Step 2: Trong primary group → 2-3 subgroups theo command pattern
        Output: 3-4 groups thay vì 300k groups
    """
    if not events:
        return []
    
    # Lấy config parameters
    primary_fields = config.get("primary_fields", [])           # parentImage, user
    similarity_fields = config.get("similarity_fields", [])     # commandLine, parentCommandLine
    similarity_threshold = config.get("similarity_threshold", 0.75)  # Ngưỡng similarity (75%)
    max_samples = config.get("max_samples_per_group", 10)      # Số events tối đa trong 1 group
    use_semantic = config.get("use_semantic_similarity", False)     # Có dùng semantic similarity không
    time_window = config.get("time_window_minutes", 120)       # Time window để nhóm (2 giờ)
    
    # Chọn function similarity phù hợp
    if use_semantic:
        similarity_func = calculate_semantic_similarity
    else:
        similarity_func = calculate_enhanced_similarity if config.get("use_enhanced_similarity") else calculate_standard_similarity
    
    # Group by time windows first để xử lý hiệu quả hơn
    if time_window > 0:
        time_groups = group_events_by_time(events, time_window)
    else:
        time_groups = {'all': events}
    
    all_deduplicated = []
    
    # Xử lý từng time window
    for time_key, time_events in time_groups.items():
        if not time_events:
            continue
        
        # print(f"\n📊 DEBUG - Processing time window: {time_key} ({len(time_events)} events)")
        
        # STEP 1: Group by PRIMARY FIELDS first (parentImage, user, etc.)
        # Mục đích: Tất cả events có cùng parentImage + user sẽ ở cùng 1 group
        primary_groups = defaultdict(list)
        
        for event in time_events:
            # Tạo primary key (CHỈ primary fields, KHÔNG có commandLine)
            primary_key_parts = []
            for field in primary_fields:
                value = safe_str(get_nested_value(event, field))
                if not value:
                    value = "MISSING"
                primary_key_parts.append(value)
            
            # Ví dụ: "C:\\Windows\\System32\\forfiles.exe|NT AUTHORITY\\SYSTEM"
            primary_key = "|".join(primary_key_parts)
            primary_groups[primary_key].append(event)
        
        print(f"  • Primary groups created: {len(primary_groups)}")
        for key, events_list in primary_groups.items():
            print(f"    - {key}: {len(events_list)} events")
        
        # STEP 2: For each primary group, apply commandLine similarity refinement
        # Mục đích: Trong cùng 1 primary group, nhóm theo SIMILARITY thực tế (không phải pattern)
        for primary_key, primary_events in primary_groups.items():
            if len(primary_events) == 1:
                # Single event trong primary group - không cần commandLine refinement
                event = primary_events[0].copy()
                event['_group_info'] = {
                    'total_events_in_group': 1,
                    'time_window': time_key,
                    'primary_key': primary_key,                    # parentImage|user
                    'pattern': extract_command_pattern_enhanced(   # command pattern
                        safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
                    ),
                    'group_id': f"primary_{hashlib.md5(primary_key.encode()).hexdigest()[:8]}",
                    'first_seen': event.get('@timestamp', ''),
                    'last_seen': event.get('@timestamp', ''),
                    'unique_agents': 1,
                    'dedup_strategy': 'primary_fields_first',     # Strategy: chỉ dùng primary fields
                    'normalized_command': normalize_command_line_enhanced(
                        safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
                    )
                }
                event['_risk_score'] = calculate_risk_score(event, primary_events, config)
                all_deduplicated.append(event)
                continue
            
            # Multiple events trong primary group - apply SIMILARITY-FIRST approach
            # Mục đích: Nhóm các events có command thực sự tương tự (dựa trên similarity, không phải pattern)
            refined_groups = defaultdict(list)
            
            for event in primary_events:
                cmd_line = safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
                parent_cmd = safe_str(get_nested_value(event, 'data.win.eventdata.parentCommandLine'))
                
                # Tìm group tương tự nhất trong cùng primary group (SIMILARITY-FIRST APPROACH)
                assigned = False
                best_similarity = 0
                best_group = None
                
                for existing_pattern, existing_events in refined_groups.items():
                    representative = existing_events[0]
                    rep_cmd = safe_str(get_nested_value(representative, 'data.win.eventdata.commandLine'))
                    rep_parent_cmd = safe_str(get_nested_value(representative, 'data.win.eventdata.parentCommandLine'))
                    
                    # Tính similarity cho CẢ commandLine VÀ parentCommandLine
                    cmd_sim = similarity_func(cmd_line, rep_cmd)
                    
                    # Tính similarity cho parentCommandLine nếu có
                    parent_sim = 0
                    if parent_cmd and rep_parent_cmd:
                        parent_sim = similarity_func(parent_cmd, rep_parent_cmd)
                    
                    # Lấy similarity cao nhất giữa commandLine và parentCommandLine
                    current_sim = max(cmd_sim, parent_sim)
                    
                    # Cập nhật best similarity nếu cao hơn và đạt threshold
                    if current_sim > best_similarity and current_sim >= similarity_threshold:
                        best_similarity = current_sim
                        best_group = existing_pattern
                
                # Assign vào group tốt nhất nếu tìm thấy
                if best_group:
                    refined_groups[best_group].append(event)
                    assigned = True
                
                # Tạo refined group mới nếu không assign được
                if not assigned:
                    # Sử dụng pattern để tạo group mới (chỉ để organize và labeling, KHÔNG phải để quyết định grouping)
                    # Pattern chỉ là tên gọi cho group, không ảnh hưởng đến việc nhóm events
                    pattern = extract_command_pattern_enhanced(cmd_line)
                    if pattern not in refined_groups:
                        refined_groups[pattern] = []
                    refined_groups[pattern].append(event)
            
            # Tạo final representatives cho mỗi refined group
            for pattern, pattern_events in refined_groups.items():
                representative = pattern_events[0].copy()
                
                representative['_group_info'] = {
                    'total_events_in_group': len(pattern_events),
                    'time_window': time_key,
                    'primary_key': primary_key,                    # parentImage|user
                    'pattern': pattern,                            # command pattern
                    'group_id': f"primary_{hashlib.md5(primary_key.encode()).hexdigest()[:8]}_{pattern}",
                    'first_seen': min(e.get('@timestamp', '') for e in pattern_events),
                    'last_seen': max(e.get('@timestamp', '') for e in pattern_events),
                    'unique_agents': len(set(e.get('agent', {}).get('name', 'unknown') for e in pattern_events)),
                    'dedup_strategy': 'similarity_first_with_pattern_labeling',  # Strategy: similarity-first, pattern chỉ để label
                    'normalized_command': normalize_command_line_enhanced(
                        safe_str(get_nested_value(representative, 'data.win.eventdata.commandLine'))
                    )
                }
                
                representative['_risk_score'] = calculate_risk_score(representative, pattern_events, config)
                all_deduplicated.append(representative)
    
    return all_deduplicated

# Keep original function as backup
def advanced_similarity_dedup(events: List[Dict], config: Dict) -> List[Dict]:
    """Original deduplication - wrapper to enhanced version"""
    return advanced_similarity_dedup_v2(events, config)


# --- RISK SCORING ---

def calculate_risk_score(representative: Dict, all_events: List[Dict], config: Dict) -> Dict:
    """
    Tính toán risk score cho group dựa trên nhiều tiêu chí
    
    Mục đích: Đánh giá mức độ rủi ro của một group events để ưu tiên xử lý
    
    Args:
        representative: Event đại diện cho group
        all_events: Tất cả events trong group
        config: Config dedup
    
    Returns:
        Dictionary chứa các risk scores:
        - total_score: Tổng điểm rủi ro (0-1)
        - frequency_score: Điểm tần suất (0-1)
        - time_score: Điểm thời gian (0-1)
        - pattern_risk: Điểm pattern rủi ro (0-1)
        - agent_diversity: Điểm đa dạng agent (0-1)
    
    Scoring logic:
    1. Frequency: Càng nhiều events càng rủi ro
    2. Time span: Càng kéo dài càng rủi ro
    3. Pattern: Commands đáng ngờ (powershell -enc, rundll32, etc.)
    4. Agent diversity: Càng nhiều agents khác nhau càng rủi ro
    """
    
    # Frequency score (0-1) - Tần suất xuất hiện
    event_count = len(all_events)
    frequency_score = min(event_count / 1000, 1.0)  # Cap at 1000 events
    
    # Time span score - Khoảng thời gian events xuất hiện
    timestamps = [e.get('@timestamp', '') for e in all_events if e.get('@timestamp')]
    if len(timestamps) > 1:
        try:
            times = [datetime.fromisoformat(t.replace('Z', '+00:00')) for t in timestamps]
            time_span = (max(times) - min(times)).total_seconds() / 3600  # hours
            time_score = min(time_span / 24, 1.0)  # Cap at 24 hours
        except:
            time_score = 0.0
    else:
        time_score = 0.0
    
    # Pattern-based risk - Rủi ro dựa trên loại command
    pattern_risk = 0.0
    cmd_line = safe_str(get_nested_value(representative, 'data.win.eventdata.commandLine'))
    
    # Danh sách các indicators đáng ngờ
    suspicious_indicators = [
        'powershell -enc', 'invoke-webrequest', 'downloadstring',
        'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript',
        'certutil -decode', 'bitsadmin', 'net user', 'whoami'
    ]
    
    # Cộng điểm rủi ro cho mỗi indicator
    for indicator in suspicious_indicators:
        if indicator in cmd_line.lower():
            pattern_risk += 0.2
    
    pattern_risk = min(pattern_risk, 1.0)  # Cap at 1.0
    
    # Agent diversity (nhiều agents = riskier) - Đa dạng agent
    unique_agents = len(set(e.get('agent', {}).get('name', 'unknown') for e in all_events))
    agent_score = min(unique_agents / 10, 1.0)  # Cap at 10 agents
    
    # Combined score - Kết hợp các điểm với trọng số
    final_score = (frequency_score * 0.3 + time_score * 0.2 + pattern_risk * 0.4 + agent_score * 0.1)
    
    return {
        'total_score': round(final_score, 3),
        'frequency_score': round(frequency_score, 3), 
        'time_score': round(time_score, 3),
        'pattern_risk': round(pattern_risk, 3),
        'agent_diversity': round(agent_score, 3)
    }


# --- DATA FETCHING ---

def fetch_events_in_chunks(rule_id: str, password: str) -> Generator[List[Dict], None, None]:
    """
    Fetch events từ Wazuh Indexer theo chunks để xử lý hiệu quả
    
    Mục đích: 
    1. Tránh memory overflow khi xử lý hàng triệu events
    2. Xử lý streaming - xử lý từng chunk một
    3. Sử dụng pagination với search_after để lấy dữ liệu liên tục
    
    Args:
        rule_id: ID của rule cần lấy events
        password: Password cho Wazuh Indexer
    
    Yields:
        List các events (mỗi chunk có thể có 5000 events)
    
    Strategy:
    1. Sử dụng search_after token để pagination
    2. Mỗi request lấy FETCH_SIZE_PER_PAGE events
    3. Tiếp tục cho đến khi không còn events
    """
    search_url = f"{INDEXER_DOMAIN}/wazuh-alert*/_search"
    headers = {'Content-Type': 'application/json', 'User-Agent': USER_AGENT}
    search_after_token = None
    
    print(f"\n--- [ Rule ID: {rule_id} ] ---")
    print(f"🚀 Bắt đầu enhanced streaming processing...")

    while True:
        # Tạo query body cho Elasticsearch
        query_body = {
            "size": FETCH_SIZE_PER_PAGE,  # Số events mỗi request
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.id": rule_id}},           # Filter theo rule ID
                        {"range": {"@timestamp": {"gte": TIME_RANGE}}}  # Filter theo thời gian (UTC+7, Giờ Việt Nam)
                    ]
                }
            },
            "sort": [{"@timestamp": "desc"}, {"_id": "asc"}]  # Sort để pagination
        }

        # Thêm search_after token nếu có (pagination)
        if search_after_token:
            query_body["search_after"] = search_after_token
        
        try:
            # Gửi request đến Wazuh Indexer
            response = requests.get(
                search_url, 
                auth=(INDEXER_USER, password), 
                headers=headers, 
                json=query_body, 
                verify=False,  # Tắt SSL verification
                timeout=180    # Timeout 3 phút
            )
            response.raise_for_status()
            data = response.json()
            hits = data.get('hits', {}).get('hits', [])

            if not hits:
                print("ℹ️ Không còn events để tải.")
                break

            # Yield events từ chunk hiện tại
            yield [hit['_source'] for hit in hits]
            
            # Lấy search_after token cho chunk tiếp theo
            search_after_token = hits[-1]['sort']
            
        except Exception as e:
            print(f"❌ Lỗi khi tải dữ liệu: {e}")
            break


# --- ENHANCED ANALYSIS & REPORTING ---

def analyze_rule_streaming_v2(rule_id: str, password: str):
    """
    Enhanced streaming analysis - Hàm chính xử lý analysis cho 1 rule
    
    Mục đích: 
    1. Fetch events từ Wazuh Indexer theo chunks
    2. Áp dụng deduplication với primary fields first strategy
    3. Merge results từ các chunks
    4. Tạo báo cáo chi tiết
    
    Args:
        rule_id: ID của rule cần analyze
        password: Password cho Wazuh Indexer
    
    Execution Flow:
    1. Fetch events theo chunks (5000 events/chunk)
    2. Xác định config dedup cho loại event
    3. Khởi tạo StreamingDeduplicatorV2
    4. Xử lý từng chunk với advanced_similarity_dedup_v2
    5. Merge results vào global groups
    6. Cleanup memory định kỳ
    7. Tạo final results và báo cáo
    """
    print(f"📊 Đang phân tích Rule ID: {rule_id} (Enhanced Streaming Mode)")
    
    deduplicator = None
    total_events_processed = 0
    config = None
    
    # Xử lý từng chunk events
    for chunk_number, chunk in enumerate(fetch_events_in_chunks(rule_id, password), 1):
        total_events_processed += len(chunk)
        print(f"  -> Chunk {chunk_number}: {len(chunk)} events | Total: {total_events_processed:,}")
        
        # Xác định config dedup cho chunk đầu tiên
        if config is None and chunk:
            # Sử dụng enhanced config dựa trên rule groups
            base_config = determine_dedup_config(chunk[0])
            config = DEDUP_CONFIG_BY_GROUP_ENHANCED.get(
                base_config['event_type'], 
                DEDUP_CONFIG_BY_GROUP_ENHANCED["default"]
            )
            deduplicator = StreamingDeduplicatorV2(config)
            print(f"  -> Enhanced dedup strategy: {config['event_type']}")
            print(f"  -> Similarity threshold: {config['similarity_threshold']}")
            print(f"  -> Semantic similarity: {config.get('use_semantic_similarity', False)}")
            print(f"  -> Primary fields: {config.get('primary_fields', [])}")
            print(f"  -> Similarity fields: {config.get('similarity_fields', [])}")
        
        if deduplicator:
            # Áp dụng enhanced dedup function cho chunk hiện tại
            chunk_groups = advanced_similarity_dedup_v2(chunk, config)
            
            # Merge results vào global groups
            deduplicator.merge_groups_into_global(chunk_groups)
            deduplicator.processed_count = total_events_processed
            
            # Cleanup memory định kỳ
            if total_events_processed % MEMORY_CLEANUP_INTERVAL == 0:
                deduplicator.cleanup_memory()
            
            # Giải phóng memory cho chunk hiện tại
            del chunk, chunk_groups
            gc.collect()
        
        # Kiểm tra giới hạn số events xử lý
        if total_events_processed >= MAX_EVENTS_TO_PROCESS:
            print(f"  -> Reached limit {MAX_EVENTS_TO_PROCESS:,} events.")
            break
    
    # Kiểm tra kết quả
    if not deduplicator or not deduplicator.global_groups:
        print("✅ No events or groups found.")
        return
    
    # Lấy final results
    final_results = deduplicator.get_final_results()
    
    # Enhanced reporting
    print(f"\n--- ENHANCED DEDUPLICATION REPORT ---")
    print(f"Rule ID: {rule_id}")
    print(f"Total events processed: {total_events_processed:,}")
    print(f"Unique behaviors found: {len(final_results):,}")
    print(f"Reduction ratio: {(1 - len(final_results)/max(total_events_processed, 1))*100:.1f}%")
    
    # Pattern breakdown - Phân tích theo patterns
    pattern_counts = defaultdict(int)
    total_events_by_pattern = defaultdict(int)
    for result in final_results:
        pattern = result.get('_group_info', {}).get('pattern', 'unknown')
        pattern_counts[pattern] += 1
        total_events_by_pattern[pattern] += result.get('_group_info', {}).get('total_events_in_group', 1)
    
    print(f"\n--- PATTERN BREAKDOWN ---")
    for pattern in sorted(pattern_counts.keys()):
        groups = pattern_counts[pattern]
        events = total_events_by_pattern[pattern]
        print(f"  {pattern}: {groups:,} groups ({events:,} total events)")
    
    # Tạo báo cáo chi tiết
    create_comprehensive_report_v2(final_results, rule_id, config)

def create_comprehensive_report_v2(events: List[Dict], rule_id: str, config: Dict):
    """Enhanced reporting với better insights và primary fields focus"""
    if not events:
        return
    
    events_sorted = sorted(events, key=lambda x: (
        x.get('_risk_score', {}).get('total_score', 0),
        x.get('_group_info', {}).get('total_events_in_group', 0)
    ), reverse=True)
    
    summary_data = []
    
    for event in events_sorted:
        group_info = event.get('_group_info', {})
        risk_score = event.get('_risk_score', {})
        
        row = {
            "event_count": group_info.get('total_events_in_group', 1),
            "risk_score": risk_score.get('total_score', 0),
            "pattern": group_info.get('pattern', 'unknown'),
            "primary_key": group_info.get('primary_key', 'N/A')[:80] + ('...' if len(group_info.get('primary_key', '')) > 80 else ''),
            "first_seen": group_info.get('first_seen', 'N/A')[:19],
            "last_seen": group_info.get('last_seen', 'N/A')[:19],
            "dedup_strategy": group_info.get('dedup_strategy', 'unknown'),
            "normalized_command": group_info.get('normalized_command', 'N/A')[:100] + ('...' if len(group_info.get('normalized_command', '')) > 100 else '')
        }
        
        # Add key fields based on config
        for field in config.get("primary_fields", []):
            value = safe_str(get_nested_value(event, field))
            field_name = field.split('.')[-1]
            row[field_name] = value[:50] + ('...' if len(value) > 50 else '')
        
        # Add original command line for reference
        original_cmd = safe_str(get_nested_value(event, 'data.win.eventdata.commandLine'))
        row["original_command_sample"] = original_cmd[:80] + ('...' if len(original_cmd) > 80 else '')
        
        summary_data.append(row)
    
    df = pd.DataFrame(summary_data)
    
    print(f"\n--- TOP BEHAVIORS (Primary Fields First Grouping) ---")
    print(df.head(15).to_string(index=False))
    
    # Export
    try:
        filename = f"enhanced_dedup_rule_{rule_id}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        df.to_csv(filename, index=False, encoding='utf-8-sig')
        print(f"\n💾 Enhanced report exported: {filename}")
    except Exception as e:
        print(f"\n❌ Export error: {e}")
    
    # Primary fields grouping analysis
    print(f"\n--- PRIMARY FIELDS GROUPING ANALYSIS ---")
    primary_key_counts = df.groupby('primary_key')['event_count'].sum().sort_values(ascending=False)
    print(f"Top primary field combinations:")
    for primary_key, total_events in primary_key_counts.head(10).items():
        print(f"  • {total_events:,} events: {primary_key}")
    
    # Pattern breakdown within primary groups
    print(f"\n--- PATTERN BREAKDOWN WITHIN PRIMARY GROUPS ---")
    pattern_stats = df.groupby(['primary_key', 'pattern']).agg({
        'event_count': ['sum', 'count']
    }).round(3)
    
    pattern_stats.columns = ['total_events', 'groups']
    print(pattern_stats.head(20))
    
    # Detailed statistics by pattern
    print(f"\n--- DETAILED PATTERN STATISTICS ---")
    pattern_stats_overall = df.groupby('pattern').agg({
        'event_count': ['count', 'sum', 'mean', 'max'],
        'risk_score': ['mean', 'max']
    }).round(3)
    
    pattern_stats_overall.columns = ['groups', 'total_events', 'avg_events_per_group', 'max_events_in_group', 'avg_risk', 'max_risk']
    print(pattern_stats_overall)
    
    # High volume groups analysis
    high_volume_groups = df[df['event_count'] >= 1000]
    if not high_volume_groups.empty:
        print(f"\n--- HIGH VOLUME GROUPS (>=1000 events) ---")
        print(f"Found {len(high_volume_groups)} high-volume groups:")
        for _, row in high_volume_groups.head(10).iterrows():
            print(f"  • {row['event_count']:,} events - {row['pattern']} - {row['primary_key']}")
    
    # Dedup strategy effectiveness
    print(f"\n--- DEDUPLICATION STRATEGY EFFECTIVENESS ---")
    strategy_stats = df.groupby('dedup_strategy').agg({
        'event_count': ['sum', 'count']
    })
    strategy_stats.columns = ['total_events', 'groups']
    print(strategy_stats)


# --- LEGACY FUNCTIONS (Keep for compatibility) ---

class StreamingDeduplicator:
    """Legacy class - redirects to enhanced version"""
    def __init__(self, config: Dict):
        self.enhanced = StreamingDeduplicatorV2(config)
        self.global_groups = self.enhanced.global_groups
        self.processed_count = self.enhanced.processed_count
    
    def merge_groups_into_global(self, chunk_groups: List[Dict]) -> None:
        return self.enhanced.merge_groups_into_global(chunk_groups)
    
    def cleanup_memory(self) -> None:
        return self.enhanced.cleanup_memory()
    
    def get_final_results(self) -> List[Dict]:
        return self.enhanced.get_final_results()

def analyze_rule_streaming(rule_id: str, password: str):
    """Legacy function - redirects to enhanced version"""
    return analyze_rule_streaming_v2(rule_id, password)

def create_comprehensive_report(events: List[Dict], rule_id: str, config: Dict):
    """Legacy function - redirects to enhanced version"""
    return create_comprehensive_report_v2(events, rule_id, config)


# --- MAIN FUNCTIONS ---

def main_enhanced():
    """Enhanced main function với Primary Fields First strategy"""
    print("=" * 70)
    print("     ENHANCED STREAMING LOG DEDUPLICATION TOOL")
    print("     PRIMARY FIELDS FIRST STRATEGY")
    print("=" * 70)
    print(f"💾 Memory limit: {MAX_GROUPS_IN_MEMORY:,} groups")
    print(f"⚡ Chunk size: {CHUNK_SIZE:,} events")
    print(f"🎯 Max processing: {MAX_EVENTS_TO_PROCESS:,} events")
    print(f"🧠 Enhanced deduplication: ENABLED")
    print(f"🔍 Semantic similarity: ENABLED")
    print(f"🎯 PRIMARY FIELDS FIRST: ENABLED (parentImage + user)")
    print(f"📊 CommandLine similarity: SECONDARY (refinement only)")
    print(f"⚖️ Similarity threshold: 0.75 (reduced for better grouping)")
    print(f"🕐 Timezone: UTC+7 (Giờ Việt Nam)")
    print(f"📅 Time range: {TIME_RANGE}")
    
    try:
        password = getpass(f"Nhập mật khẩu cho user '{INDEXER_USER}': ")
    except Exception as e:
        print(f"❌ Password input error: {e}")
        return
    
    for rule_id in RULES_TO_MONITOR:
        try:
            analyze_rule_streaming_v2(rule_id, password)
            print("-" * 70)
        except Exception as e:
            print(f"❌ Error analyzing rule {rule_id}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n✅ Enhanced streaming analysis completed!")
    print("📊 Results now prioritize primary fields (parentImage, user) over commandLine patterns")
    print(f"🕐 Data queried using UTC+7 timezone (Giờ Việt Nam)")
    print(f"📅 Time range: {TIME_RANGE}")

def main():
    """Original main function - now uses enhanced logic"""
    return main_enhanced()


if __name__ == "__main__":
    main()