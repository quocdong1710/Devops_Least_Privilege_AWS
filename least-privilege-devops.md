# Báo Cáo: Hướng Dẫn Phân Quyền Hạn Tối Thiểu (Least Privilege) Cho Các Vai Trò DevOps Trong AWS DevOps Agent

## 1. Tổng Quan Tầm Quan Trọng Của Nguyên Tắc Least Privilege
Nguyên tắc quyền hạn tối thiểu (Least Privilege) đóng vai trò then chốt trong việc bảo vệ cơ sở hạ tầng đám mây. Đối với dịch vụ **AWS DevOps Agent**, việc áp dụng Least Privilege giúp ngăn ngừa rủi ro giả mạo danh tính, hạn chế tối đa phạm vi tác động (blast radius) khi xảy ra sự cố bảo mật, và đảm bảo tính tuân thủ quy định dữ liệu.

AWS DevOps Agent áp dụng kiến trúc phân quyền đa lớp:
- **Identity-based Policies:** Khai báo quyền hạn cấp cho người dùng hoặc IAM Role.
- **Permission Guardrails:** Lớp hàng rào bảo mật do AWS thiết lập cố định, chặn toàn bộ các lệnh ghi/xóa trực tiếp (như `ec2:TerminateInstances`, `s3:PutObject`, `dynamodb:DeleteItem`) đối với Agent.
- **Dynamic Tagging & Resource Scoping:** Giới hạn quyền truy cập theo từng Agent Space thông qua thẻ tag động `${aws:PrincipalTag/AgentSpaceId}`.

---

## 2. Phân Quyền Chi Tiết Theo Các Vai Trò Vận Hành (Personas)

### 2.1. Vai Trò 1: Kỹ Sư Thiết Lập & Quản Trị Hệ Thống (DevOps Admin / Cloud Architect)
* **Phạm vi công việc:** Khởi tạo không gian làm việc (`Agent Space`), cấu hình kết nối tài khoản AWS phụ (multi-account), bật ứng dụng Operator Web App, tích hợp SSO/Identity Center hoặc External IdP (Okta, Entra ID), và thiết lập các kết nối riêng tư VPC PrivateLink.
* **Tập hợp IAM Actions cần thiết:**
  * `aidevops:CreateAgentSpace`, `aidevops:UpdateAgentSpace`, `aidevops:DeleteAgentSpace`
  * `aidevops:EnableOperatorApp`, `aidevops:DisableOperatorApp`, `aidevops:UpdateOperatorAppIdpConfig`
  * `aidevops:AssociateService`, `aidevops:DisassociateService`
  * `aidevops:CreatePrivateConnection`, `aidevops:DeletePrivateConnection`
  * `sso:CreateApplicationAssignment`, `sso:DeleteApplicationAssignment`
  * `iam:CreateServiceLinkedRole`

#### JSON Policy mẫu cho DevOps Admin:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DevOpsAgentAdminPermissions",
      "Effect": "Allow",
      "Action": [
        "aidevops:CreateAgentSpace",
        "aidevops:GetAgentSpace",
        "aidevops:UpdateAgentSpace",
        "aidevops:DeleteAgentSpace",
        "aidevops:EnableOperatorApp",
        "aidevops:DisableOperatorApp",
        "aidevops:UpdateOperatorAppIdpConfig",
        "aidevops:AssociateService",
        "aidevops:DisassociateService",
        "aidevops:CreatePrivateConnection",
        "aidevops:DeletePrivateConnection"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowServiceLinkedRoleCreation",
      "Effect": "Allow",
      "Action": "iam:CreateServiceLinkedRole",
      "Resource": "arn:aws:iam::*:role/aws-service-role/aidevops.amazonaws.com/*",
      "Condition": {
        "StringEquals": {
          "iam:AWSServiceName": "aidevops.amazonaws.com"
        }
      }
    }
  ]
}
```

---

### 2.2. Vai Trò 2: Kỹ Sư Trực Ca & Xử Lý Sự Cố (DevOps Operator / SRE)
* **Phạm vi công việc:** Tương tác hàng ngày qua Operator Web App, chat bằng ngôn ngữ tự nhiên để truy vấn hạ tầng, theo dõi các cuộc điều tra sự cố (Incidents RCA), xem nhật ký suy luận từng bước (journal records), khám phá sơ đồ liên kết (topology) và phê duyệt kế hoạch giảm thiểu tác động.
* **Tập hợp IAM Actions cần thiết:**
  * `aidevops:CreateChat`, `aidevops:SendMessage`, `aidevops:ListChats`
  * `aidevops:ListExecutions`, `aidevops:ListJournalRecords`
  * `aidevops:DiscoverTopology`
  * `aidevops:ListRecommendations`, `aidevops:GetRecommendation`
  * `aidevops:CreateBacklogTask`, `aidevops:UpdateBacklogTask`

#### JSON Policy mẫu cho DevOps Operator (`AIDevOpsOperatorAppAccessPolicy` giới hạn theo AgentSpaceId):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOperatorScopedToAgentSpace",
      "Effect": "Allow",
      "Action": [
        "aidevops:CreateChat",
        "aidevops:SendMessage",
        "aidevops:ListChats",
        "aidevops:ListExecutions",
        "aidevops:ListJournalRecords",
        "aidevops:DiscoverTopology",
        "aidevops:ListRecommendations",
        "aidevops:GetRecommendation",
        "aidevops:CreateBacklogTask",
        "aidevops:UpdateBacklogTask",
        "aidevops:GetAgentSpace"
      ],
      "Resource": "arn:aws:aidevops:*:*:agentspace/${aws:PrincipalTag/AgentSpaceId}",
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "${aws:PrincipalAccount}"
        }
      }
    },
    {
      "Sid": "AllowAccountUsageAccess",
      "Effect": "Allow",
      "Action": ["aidevops:GetAccountUsage"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": "${aws:PrincipalAccount}"
        }
      }
    }
  ]
}
```

---

### 2.3. Vai Trò 3: Chuyên Gia Đào Tạo & Quản Lý Tri Thức (Knowledge Manager)
* **Phạm vi công việc:** Quản lý các tài sản tri thức (Assets), soạn thảo tệp hướng dẫn standing `AGENTS.md` (giới hạn 25 KB), đóng gói và tải lên các quy trình xử lý lỗi tiêu chuẩn dưới dạng **Skills** (file `.zip` tối đa 6 MB hoặc từ GitHub repository), cũng như quản lý các **Memories**.
* **Tập hợp IAM Actions cần thiết:**
  * `aidevops:CreateAsset`, `aidevops:GetAsset`, `aidevops:UpdateAsset`, `aidevops:DeleteAsset`
  * `aidevops:CreateAssetFile`, `aidevops:GetAssetFile`, `aidevops:UpdateAssetFile`, `aidevops:DeleteAssetFile`
  * `aidevops:ListAssets`, `aidevops:GetAssetContent`, `aidevops:ListAssetVersions`
  * `aidevops:ListAssetTypes` (yêu cầu `Resource: "*"` vì là API dùng chung toàn hệ thống)

#### JSON Policy mẫu cho Knowledge Manager:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssetManagementScopedToSpace",
      "Effect": "Allow",
      "Action": [
        "aidevops:CreateAsset",
        "aidevops:GetAsset",
        "aidevops:UpdateAsset",
        "aidevops:DeleteAsset",
        "aidevops:ListAssets",
        "aidevops:GetAssetContent",
        "aidevops:CreateAssetFile",
        "aidevops:GetAssetFile",
        "aidevops:UpdateAssetFile",
        "aidevops:DeleteAssetFile",
        "aidevops:ListAssetFiles"
      ],
      "Resource": "arn:aws:aidevops:*:*:agentspace/${aws:PrincipalTag/AgentSpaceId}"
    },
    {
      "Sid": "AllowGlobalAssetTypesListing",
      "Effect": "Allow",
      "Action": "aidevops:ListAssetTypes",
      "Resource": "*"
    }
  ]
}
```

---

### 2.4. Vai Trò 4: Kỹ Sư Bảo Mật & Kiểm Toán Hệ Thống (Security Auditor)
* **Phạm vi công việc:** Rà soát cấu hình an ninh, giám sát việc xoay vòng Access Token kết nối server từ xa, kiểm tra hạn mức giờ điều tra hàng tháng (`GetAccountUsage`), và kiểm tra việc tuân thủ quy trình vận hành mà không thực hiện hành động can thiệp hay chat.
* **Tập hợp IAM Actions cần thiết (Chỉ đọc - Read Only):**
  * `aidevops:GetAgentSpace`, `aidevops:ListAgentSpaces`
  * `aidevops:ListAssociations`, `aidevops:GetAssociation`
  * `aidevops:ListExecutions`, `aidevops:ListJournalRecords`
  * `aidevops:ListRecommendations`, `aidevops:GetRecommendation`
  * `aidevops:ListAssets`, `aidevops:GetAsset`, `aidevops:GetAssetContent`
  * `aidevops:GetAccountUsage`

#### JSON Policy mẫu cho Security Auditor (`AIDevOpsAgentReadOnlyAccess`):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AIDevOpsAgentReadOnlyPermissions",
      "Effect": "Allow",
      "Action": [
        "aidevops:DescribePrivateConnection",
        "aidevops:DescribeServices",
        "aidevops:Get*",
        "aidevops:List*",
        "aidevops:SearchServiceAccessibleResource"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 3. Cơ Chế Permission Guardrails & Kiểm Soát Ranh Giới
1. **Mức trần bảo mật (Permission Ceiling):** Dù kỹ sư có cấu hình gán quyền Administrator cho IAM Role của Agent Space, hệ thống **Permission Guardrail** của AWS vẫn áp đặt mức trần Read-Only. Mọi hành động can thiệp vật lý (như xóa S3 object, terminate EC2) đều bị chặn ở cấp độ hạ tầng dịch vụ.
2. **Ngăn chặn lỗ hổng Confused Deputy:** Tất cả Trust Policies của Agent Space Role và Cross-Account Role bắt buộc phải chứa các điều kiện:
   * `"aws:SourceAccount": "<MONITORING_ACCOUNT_ID>"`
   * `"ArnLike": { "aws:SourceArn": "arn:aws:aidevops:<REGION>:<ACCOUNT_ID>:agentspace/*" }`

---

## 4. Quy Trình Giảm Quyền Thừa Nâng Cao (IAM Policy Optimization)
Để duy trì trạng thái Least Privilege tối ưu theo thời gian, doanh nghiệp cần triển khai quy trình 3 bước:
1. **Kiểm tra Last Accessed (Access Advisor):** Định kỳ kiểm tra tab Access Advisor trên IAM Console để phát hiện các dịch vụ/action không được Agent hoặc Operator truy cập trong vòng 90 ngày.
2. **Phân tích CloudTrail Logs:** Rà soát lịch sử gọi API thực tế từ CloudTrail để thay thế các ký tự đại diện (`*`) bằng danh sách Action chính xác.
3. **Sử dụng IAM Access Analyzer:** Tự động phát hiện các chính sách lỏng lẻo và khởi tạo lại Policy template chuẩn dựa trên dữ liệu CloudTrail lịch sử.
