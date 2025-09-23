# Sơ đồ và Cách hoạt động của Trang QR Generator

## Tổng quan
Trang QR Generator (`/qr`) là một công cụ tạo mã QR với nhiều chức năng khác nhau, bao gồm tạo QR đơn lẻ, hàng loạt, xử lý file Excel và in QR codes.

## Sơ đồ Kiến trúc

## Hệ thống và Triển khai (System & Deployment)

### Tổng quan
Hệ thống được thiết lập để tự động triển khai (CI/CD) từ GitHub đến PythonAnywhere mỗi khi có commit mới vào nhánh `main`.

### Quy trình CI/CD với GitHub Actions
1.  **Trigger**: `push` đến nhánh `main`.
2.  **Job `deploy-to-pythonanywhere`**:
    *   **Checkout code**: Lấy mã nguồn mới nhất từ repository.
    *   **SSH vào PythonAnywhere**: Sử dụng `appleboy/ssh-action` với thông tin đăng nhập được lưu trong GitHub Secrets (`PA_USERNAME`, `PA_API_TOKEN`).
    *   **Điều hướng đến thư mục dự án**: `cd ~/tongtongong.pythonanywhere.com`.
    *   **Kéo code mới nhất**: `git pull`.
    *   **Tạo/Kích hoạt Môi trường ảo**:
        *   Kiểm tra sự tồn tại của môi trường ảo `my-cicd-venv`.
        *   Nếu chưa có, tạo mới bằng `python3.10 -m venv my-cicd-venv`.
        *   Kích hoạt môi trường ảo: `source my-cicd-venv/bin/activate`.
    *   **Cài đặt Dependencies**:
        *   Cài đặt các thư viện từ `requirements.txt` vào môi trường ảo.
        *   Sử dụng cờ `--no-cache-dir` để tránh làm đầy bộ nhớ cache trên PythonAnywhere.
    *   **Reload Web App**: Gửi yêu cầu POST đến API của PythonAnywhere để tải lại ứng dụng web, áp dụng các thay đổi mới.

### Quản lý Dependencies
- Tất cả các thư viện Python cần thiết cho dự án được quản lý trong một file duy nhất: `requirements.txt`.
- Việc cài đặt được thực hiện trong một môi trường ảo (`my-cicd-venv`) để tránh xung đột và các vấn đề về bộ nhớ với hệ thống global của PythonAnywhere.

### Dọn dẹp và Tối ưu
- **`.gitignore`**: File `.gitignore` được cấu hình để bỏ qua các file không cần thiết (file credentials, file tạm, file cấu hình local, các file markdown ghi chú cá nhân) khỏi repository.
- **Dọn dẹp lịch sử**: Các file nhạy cảm hoặc không cần thiết đã được đẩy lên GitHub sẽ được xóa khỏi lịch sử Git để giữ cho repository sạch sẽ và an toàn.

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRANG QR GENERATOR                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐              ┌─────────────────────────┐   │
│  │   INPUT PANEL   │              │     PREVIEW PANEL       │   │
│  │   (col-lg-5)    │              │     (col-lg-7)          │   │
│  │                 │              │                         │   │
│  │ ┌─────────────┐ │              │ ┌─────────────────────┐ │   │
│  │ │ Tạo QR      │ │              │ │   Loading Spinner   │ │   │
│  │ │ Hàng loạt   │ │              │ └─────────────────────┘ │   │
│  │ └─────────────┘ │              │                         │   │
│  │                 │              │ ┌─────────────────────┐ │   │
│  │ ┌─────────────┐ │              │ │   QR List Display   │ │   │
│  │ │ Xử lý Excel │ │              │ │   - QR Images       │ │   │
│  │ └─────────────┘ │              │ │   - Text Labels     │ │   │
│  │                 │              │ │   - Download Btns   │ │   │
│  │ ┌─────────────┐ │              │ └─────────────────────┘ │   │
│  │ │ Cài đặt     │ │              │                         │   │
│  │ │ Bố cục      │ │              │ ┌─────────────────────┐ │   │
│  │ └─────────────┘ │              │ │   Paper Preview     │ │   │
│  └─────────────────┘              │ │   - Grid Layout     │ │   │
│                                   │ │   - Print Format    │ │   │
│                                   │ └─────────────────────┘ │   │
│                                   │                         │   │
│                                   │ ┌─────────────────────┐ │   │
│                                   │ │   Print Button      │ │   │
│                                   │ └─────────────────────┘ │   │
│                                   └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Luồng hoạt động chính

### 1. Tạo QR Hàng loạt
```
User Input (Textarea) → JavaScript (generateBatchQR) → Flask Backend (/qr POST) → QuickChart API → Response → Display QR List → Update Paper Preview
```

**Chi tiết:**
- User nhập danh sách text (mỗi dòng một QR)
- JavaScript chia text thành từng dòng
- Gửi từng dòng đến `/qr` endpoint
- Backend tạo URL QR qua QuickChart.io
- Hiển thị danh sách QR codes
- Cập nhật preview trang in

### 2. Xử lý File Excel
```
User Upload Excel → JavaScript (processExcelFile) → Flask Backend (/qr/excel POST) → Read Excel → Extract Column 1 → Generate QR URLs → Response → Display QR List
```

**Chi tiết:**
- User upload file Excel (.xlsx, .xls, .csv)
- Backend đọc file và lấy cột đầu tiên
- Tạo QR code cho mỗi cell (tối đa 100 items)
- Trả về danh sách QR codes
- Hiển thị và cập nhật preview

### 3. Cài đặt Bố cục và In
```
User Settings → JavaScript (updateLayout) → Update Paper Preview → Print Function → Generate Print HTML → Open Print Window
```

**Chi tiết:**
- Cài đặt: Kích thước giấy, số cột, kích thước chữ, hiển thị text
- JavaScript tính toán layout và tạo preview
- Chức năng in tạo HTML với CSS @page
- Mở cửa sổ in mới với format đã định

## Backend Routes

### `/qr` (GET, POST)
- **GET**: Render template `qr.html`
- **POST**: Tạo QR code đơn lẻ
  - Input: `{text, qr_size}`
  - Output: `{success, qr_url, text, size}`
  - Sử dụng QuickChart.io API

### `/qr/excel` (POST)
- Xử lý upload file Excel
- Input: FormData với file và qr_size
- Đọc cột đầu tiên của Excel
- Tạo QR codes hàng loạt (tối đa 100)
- Output: `{success, qr_codes[], total, message}`

## Frontend JavaScript Functions

### Core Functions
- `generateBatchQR()`: Tạo QR hàng loạt từ textarea
- `processExcelFile()`: Xử lý upload Excel
- `updateLayout()`: Cập nhật cài đặt bố cục
- `updatePaperPreview()`: Tạo preview trang in
- `printQRCodes()`: In QR codes
- `downloadQR()`: Tải xuống QR đơn lẻ

### Utility Functions
- `showLoading()` / `hideLoading()`: Hiển thị/ẩn loading
- `displayQRList()`: Hiển thị danh sách QR
- `validateInputs()`: Validate input values
- `createQRWithText()`: Tạo QR với text cho download

## Cấu hình và Tùy chọn

### Kích thước giấy hỗ trợ:
- A3 (297×420mm)
- A4 (210×297mm) - mặc định
- A5 (148×210mm)
- Letter (216×279mm)
- Custom (tùy chỉnh)

### Cài đặt bố cục:
- Số cột: 1-10 (mặc định: 3)
- Kích thước QR: 50-1000px (mặc định: 200px)
- Kích thước chữ: 6-50px (mặc định: 12px)
- Chữ đậm: có/không
- Hiển thị text: có/không

## Công nghệ sử dụng

### Backend:
- Flask (Python)
- Pandas (đọc Excel)
- QuickChart.io API (tạo QR)
- Werkzeug (upload file)

### Frontend:
- HTML5/CSS3
- Bootstrap 5
- Vanilla JavaScript
- Canvas API (download QR)
- Print API

## Tính năng nổi bật

1. **Tạo QR hàng loạt**: Hỗ trợ nhiều QR cùng lúc
2. **Xử lý Excel**: Đọc trực tiếp từ file Excel
3. **Preview trang in**: Xem trước trước khi in
4. **Tùy chỉnh layout**: Linh hoạt về bố cục và kích thước
5. **Download đơn lẻ**: Tải từng QR riêng biệt
6. **Responsive design**: Tương thích mobile

## Giới hạn và Lưu ý

- Tối đa 100 QR codes từ Excel
- Kích thước QR: 50-1000px
- Hỗ trợ file: .xlsx, .xls, .csv
- Sử dụng dịch vụ bên thứ 3 (QuickChart.io)
- Cần kết nối internet để tạo QR