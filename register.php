<?php require __DIR__ . '/config_mysqli.php'; require __DIR__ . '/csrf.php'; ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Create account</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { min-height: 100vh; display:flex; align-items:center; }
    .auth-card { max-width: 480px; width: 100%; }
  </style>
</head>
<body class="bg-light">
  <main class="container d-flex justify-content-center">
    <div class="card shadow-sm auth-card p-3 p-md-4">
      <div class="card-body">
        <h1 class="h4 mb-3 text-center">Create your account ✨</h1>

        <?php if (!empty($_SESSION['flash'])): ?>
          <div class="alert alert-danger py-2">
            <?php echo htmlspecialchars($_SESSION['flash']); unset($_SESSION['flash']); ?>
          </div>
        <?php endif; ?>

        <form method="post" action="register_process.php" novalidate>
          <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">

          <div class="mb-3">
            <label class="form-label" for="display_name">Full name</label>
            <input class="form-control" type="text" id="display_name" name="display_name" placeholder="Jane Doe" required>
          </div>

          <div class="mb-3">
            <label class="form-label" for="email">Email</label>
            <input class="form-control" type="email" id="email" name="email" placeholder="you@example.com" required>
          </div>

          <div class="mb-3">
            <label class="form-label" for="password">Password</label>
            <input class="form-control" type="password" id="password" name="password" placeholder="••••••••" required minlength="8" autocomplete="new-password">
            <div class="form-text">Use at least 8 characters, with letters and numbers.</div>
          </div>

          <div class="mb-2">
            <label class="form-label" for="password_confirm">Confirm password</label>
            <input class="form-control" type="password" id="password_confirm" name="password_confirm" placeholder="••••••••" required autocomplete="new-password">
          </div>

          <div class="form-check my-2">
            <input class="form-check-input" type="checkbox" id="tos" name="tos" required>
            <label class="form-check-label" for="tos">
              I agree to the Terms of Service
            </label>
          </div>

          <div class="d-grid mt-3">
            <button class="btn btn-primary" type="submit">Create account</button>
          </div>
        </form>

        <p class="text-center text-muted mt-3 mb-0 small">
          Already have an account? <a href="login.php" class="text-decoration-none">Sign in</a>
        </p>
      </div>
    </div>
  </main>

  <script>
    // simple client-side check to prevent mismatch submit
    document.querySelector('form')?.addEventListener('submit', function (e) {
      const p = document.getElementById('password').value;
      const c = document.getElementById('password_confirm').value;
      if (p !== c) {
        e.preventDefault();
        alert('Passwords do not match.');
      }
    });
  </script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
