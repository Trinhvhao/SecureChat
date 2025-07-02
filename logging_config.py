import logging

# Tạo logger
logger = logging.getLogger(__name__)

# Đặt mức log là DEBUG để ghi tất cả
logger.setLevel(logging.DEBUG)

# Handler cho console (stdout)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Định dạng log đơn giản, dễ đọc
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Thêm handler vào logger
logger.addHandler(console_handler)