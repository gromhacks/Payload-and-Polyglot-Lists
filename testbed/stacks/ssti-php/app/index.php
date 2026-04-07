<?php

require_once __DIR__ . '/vendor/autoload.php';

header('Content-Type: application/json');

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($uri === '/health') {
    echo json_encode('ok');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = $_POST['input'] ?? null;

if ($input === null) {
    http_response_code(400);
    echo json_encode(['output' => null, 'error' => 'Missing input field', 'time_ms' => 0]);
    exit;
}

$output = null;
$error = null;
$start = microtime(true);

try {
    switch ($uri) {
        case '/twig':
            $loader = new \Twig\Loader\ArrayLoader([]);
            $twig = new \Twig\Environment($loader);
            $template = $twig->createTemplate($input);
            $output = $template->render([]);
            break;

        case '/smarty':
            $smarty = new \Smarty\Smarty();
            $smarty->setCompileDir(sys_get_temp_dir());
            $output = $smarty->fetch('string:' . $input);
            break;

        case '/blade':
            // Simulate Blade template processing without Laravel
            // Converts Blade syntax to PHP and evaluates it
            $input = str_replace(['{{', '}}', '{!!', '!!}'], ['<?php echo ', '; ?>', '<?php echo ', '; ?>'], $input);
            $input = preg_replace('/@php\b/', '<?php ', $input);
            $input = preg_replace('/@endphp\b/', ' ?>', $input);
            ob_start();
            eval('?>' . $input);
            $output = ob_get_clean();
            break;

        default:
            http_response_code(404);
            $error = 'Unknown endpoint. Use /twig, /smarty, or /blade';
            break;
    }
} catch (\Throwable $e) {
    $error = $e->getMessage();
}

$time_ms = round((microtime(true) - $start) * 1000, 2);

echo json_encode([
    'output' => $output,
    'error' => $error,
    'time_ms' => $time_ms,
]);
