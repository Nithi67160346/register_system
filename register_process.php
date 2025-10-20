<?php
require __DIR__ . '/config_mysqli.php';
require __DIR__ . '/csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  header('Location: register.php'); exit;
}

if (!csrf_check($_POST['csrf'] ?? '')) {
  $_SESSION['flash'] = 'Invalid request. Please try again.';
  header('Location: register.php'); exit;
}

// Gather & normalize inputs
$name  = trim($_POST['display_name'] ?? '');
$email = strtolower(trim($_POST['email'] ?? ''));
$pass  = $_POST['password'] ?? '';
$confirm = $_POST['password_confirm'] ?? '';
$tos   = $_POST['tos'] ?? '';

/**
 * Basic validations
 */
$errors = [];

// Name: allow 2..80 chars
if ($name === '' || mb_strlen($name) < 2 || mb_strlen($name) > 80) {
  $errors[] = 'Please enter your full name (2–80 characters).';
}

// Email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  $errors[] = 'Please enter a valid email.';
}

// Password: 8..72 (bcrypt safe length)
if (strlen($pass) < 8 || strlen($pass) > 72) {
  $errors[] = 'Password must be 8–72 characters.';
}

// Confirm match
if ($pass !== $confirm) {
  $errors[] = 'Passwords do not match.';
}

// Terms checkbox
if ($tos !== 'on') {
  $errors[] = 'You must agree to the Terms of Service.';
}

if (!empty($errors)) {
  $_SESSION['flash'] = implode(' ', $errors);
  header('Location: register.php'); exit;
}

try {
  // Check duplicate email
  $stmt = $mysqli->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
  $stmt->bind_param('s', $email);
  $stmt->execute();
  $stmt->store_result();
  $exists = $stmt->num_rows > 0;
  $stmt->close();

  if ($exists) {
    // small delay to reduce timing side-channels
    usleep(250000);
    $_SESSION['flash'] = 'Email is already registered.';
    header('Location: register.php'); exit;
  }

  // Hash password
  $hash = password_hash($pass, PASSWORD_DEFAULT);

  // Insert user
  $stmt2 = $mysqli->prepare('
    INSERT INTO users (email, display_name, password_hash, created_at, last_login)
    VALUES (?, ?, ?, NOW(), NOW())
  ');
  $stmt2->bind_param('sss', $email, $name, $hash);
  $stmt2->execute();

  // If DB enforces unique and race condition occurs
  if ($mysqli->errno === 1062) {
    $stmt2->close();
    $_SESSION['flash'] = 'Email is already registered.';
    header('Location: register.php'); exit;
  }

  $newId = $stmt2->insert_id;
  $stmt2->close();

  // Auto sign-in
  $_SESSION['user_id'] = (int)$newId;
  $_SESSION['user_name'] = $name !== '' ? $name : $email;

  header('Location: dashboard.php'); exit;

} catch (Throwable $e) {
  // Log $e->getMessage() server-side if you have a logger
  $_SESSION['flash'] = 'Server error. Please try again.';
  header('Location: register.php'); exit;
}
