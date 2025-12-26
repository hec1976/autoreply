<?php
// sidebar.php - 1 Level, mit Icons

$currentUrl = $_SERVER['REQUEST_URI'] ?? '/';

function is_active(string $currentUrl, string $link): bool {
    if ($link === '#') return false;

    // exakt oder "beginnt mit" (damit /admin/users.php?x=1 auch aktiv ist)
    if ($currentUrl === $link) return true;
    if (strpos($currentUrl, $link) === 0 && strlen($link) > 1) return true;

    return false;
}

$menu = [
	['label' => 'Autoreply Verwaltung', 'icon' => 'bi-envelope-check',    'link' => 'index.php'],
	['label' => 'Deploy & Backup',      'icon' => 'bi-cloud-upload',      'link' => 'deploy_and_backup.php'],
	['label' => 'Autoreply Stats-Log',  'icon' => 'bi-bar-chart',         'link' => 'statslog.php'],
];
?>

<div id="sidebar" class="sidebar-menu">
    <?php foreach ($menu as $item): ?>
        <?php
            $label  = htmlspecialchars($item['label'], ENT_QUOTES, 'UTF-8');
            $icon   = htmlspecialchars($item['icon'],  ENT_QUOTES, 'UTF-8');
            $link   = $item['link'] ?? '#';
            $href   = htmlspecialchars($link, ENT_QUOTES, 'UTF-8');
            $active = ($link !== '#') && is_active($currentUrl, $link);
        ?>
        <a href="<?= $href ?>" class="<?= $active ? 'active' : '' ?>">
            <i class="bi <?= $icon ?>"></i>
            <span><?= $label ?></span>
        </a>
    <?php endforeach; ?>
</div>
