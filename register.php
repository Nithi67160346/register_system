<?php
// ใช้ของคุณเลย: มี session_start() + $mysqli อยู่ในไฟล์นี้แล้ว
require_once __DIR__ . '/config_mysqli.php';

// เปิด error เฉพาะตอนดีบัก (คอมเมนต์ทิ้งเมื่อขึ้นโปรดักชัน)
ini_set('display_errors', 1);
error_reporting(E_ALL);

// ฟังก์ชันกัน XSS
function e($str){ return htmlspecialchars($str ?? "", ENT_QUOTES, "UTF-8"); }

// สร้าง CSRF token ครั้งแรก (config_mysqli.php เรียก session_start() ให้แล้ว)
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = "";

// เก็บค่าฟอร์มเดิม
$email = $_POST['email'] ?? '';
$display_name = $_POST['name'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // ตรวจ CSRF
  if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    $errors[] = "CSRF token ไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองอีกครั้ง";
  }

  // รับค่า + normalize
  $password     = $_POST['password'] ?? '';
  $email        = strtolower(trim($_POST['email'] ?? ''));
  $display_name = trim($_POST['name'] ?? '');

  // ตรวจความถูกต้อง
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "อีเมลไม่ถูกต้อง";
  }
  if (strlen($password) < 8) {
    $errors[] = "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร";
  }
  if ($display_name === '' || mb_strlen($display_name) > 100) {
    $errors[] = "กรุณากรอกชื่อ–นามสกุล (ไม่เกิน 100 ตัวอักษร)";
  }

  if (!$errors) {
    try {
      // เช็คอีเมลซ้ำ
      $stmt = $mysqli->prepare('SELECT 1 FROM users WHERE email = ? LIMIT 1');
      $stmt->bind_param('s', $email);
      $stmt->execute();
      $stmt->store_result();
      if ($stmt->num_rows > 0) {
        $errors[] = "Email นี้ถูกใช้แล้ว";
      }
      $stmt->close();

      // บันทึก
      if (!$errors) {
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt2 = $mysqli->prepare('
          INSERT INTO users (email, display_name, password_hash, created_at, last_login)
          VALUES (?, ?, ?, NOW(), NOW())
        ');
        $stmt2->bind_param('sss', $email, $display_name, $hash);
        $stmt2->execute();
        $stmt2->close();

        $success = "สมัครสมาชิกสำเร็จ! คุณสามารถล็อกอินได้แล้ว";
        // รีเฟรช CSRF token ป้องกันโพสต์ซ้ำ
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        // เคลียร์ค่าในฟอร์ม
        $email = $display_name = '';
      }
    } catch (mysqli_sql_exception $ex) {
      if ($ex->getCode() === 1062) {
        $errors[] = "Email ซ้ำ กรุณาใช้ค่าอื่น";
      } else {
        $errors[] = "บันทึกข้อมูลไม่สำเร็จ";
        error_log('REGISTER ERROR: '.$ex->getMessage());
      }
    }
  }
}
?>
<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register</title>
  <style>
    body{font-family:system-ui, sans-serif; background:#f7f7fb; margin:0; padding:0;}
    .container{max-width:480px; margin:40px auto; background:#fff; border-radius:16px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,.06);}
    h1{margin:0 0 16px;}
    .alert{padding:12px 14px; border-radius:12px; margin-bottom:12px; font-size:14px;}
    .alert.error{background:#ffecec; color:#a40000; border:1px solid #ffc9c9;}
    .alert.success{background:#efffed; color:#0a7a28; border:1px solid #c9f5cf;}
    label{display:block; font-size:14px; margin:10px 0 6px;}
    input{width:100%; padding:12px; border-radius:12px; border:1px solid #ddd;}
    button{width:100%; padding:12px; border:none; border-radius:12px; margin-top:14px; background:#3b82f6; color:#fff; font-weight:600; cursor:pointer;}
    button:hover{filter:brightness(.95);}
    .hint{font-size:12px; color:#666;}
  </style>
</head>
<body>
  <div class="container">
    <h1>สมัครสมาชิก</h1>

    <?php if ($errors): ?>
      <div class="alert error">
        <?php foreach ($errors as $m) echo "<div>".e($m)."</div>"; ?>
      </div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="alert success"><?= e($success) ?></div>
    <?php endif; ?>

    <form method="post" action="">
      <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">

      <label>Email</label>
      <input type="email" name="email" value="<?= e($email) ?>" required>

      <label>ชื่อ–นามสกุล</label>
      <input type="text" name="name" value="<?= e($display_name) ?>" required>
      <div class="hint">ไม่เกิน 100 ตัวอักษร</div>

      <label>Password</label>
      <input type="password" name="password" required>
      <div class="hint">อย่างน้อย 8 ตัวอักษร</div>

      <button type="submit">สมัครสมาชิก</button>
    </form>
  </div>
</body>
</html>
