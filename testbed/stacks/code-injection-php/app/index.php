<?php

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
        case '/eval':
            ob_start();
            $result = eval('return ' . $input . ';');
            $buffered = ob_get_clean();
            $output = $buffered !== '' ? $buffered : (string)$result;
            break;

        case '/system':
            ob_start();
            system($input);
            $output = ob_get_clean();
            break;

        case '/assert':
            ob_start();
            // assert() as a code execution sink (PHP 8 evaluates string expressions)
            @assert($input);
            $buffered = ob_get_clean();
            $output = $buffered !== '' ? $buffered : 'executed';
            break;

        default:
            http_response_code(404);
            $error = 'Unknown endpoint. Use /eval, /system, or /assert';
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
