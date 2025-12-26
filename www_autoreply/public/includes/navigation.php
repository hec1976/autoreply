<?php
// === Einfache Navbar ===
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/* ---- Escaping-Helper ---- */
if (!function_exists('simple_esc')) {
    function simple_esc($s): string {
        return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

/* ---- Logo-Fallback ---- */
$logoPath1 = 'assets/img/autoresponder.png';
$logoPath2 = '../assets/img/autoresponder.png';
$logoSrc   = file_exists($logoPath1) ? $logoPath1 : (file_exists($logoPath2) ? $logoPath2 : 'assets/img/placeholder.png');
?>

<!-- ===== Navbar HTML ===== -->
<nav class="navbar-simple">
  <div class="navbar-content">
    <!-- Bild/Logo -->
    <img src="<?= simple_esc($logoSrc) ?>" alt="Logo" class="navbar-logo">
    <!-- Titel -->
    <span class="navbar-title"><strong>Autoresponder Console</strong></span>
  </div>
</nav>