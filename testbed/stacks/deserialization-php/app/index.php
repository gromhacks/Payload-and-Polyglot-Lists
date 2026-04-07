<?php

header('Content-Type: application/json');

// Autoloader that throws errors for unknown classes - simulates frameworks
spl_autoload_register(function ($class) {
    // If class has a namespace (backslash), it looks like a framework class
    if (strpos($class, '\\') !== false) {
        throw new \RuntimeException("Autoload failed: class '$class' not found (framework not installed)");
    }
});

class VulnClass {
    public $cmd;

    public function __destruct() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }

    public function __wakeup() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }

    public function __toString() {
        if ($this->cmd) {
            ob_start();
            system($this->cmd);
            return ob_get_clean();
        }
        return '';
    }
}

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
        case '/unserialize':
            // Replace literal \0 text with actual NUL bytes for protected/private property markers
            $input = str_replace('\\0', "\0", $input);
            ob_start();
            $obj = unserialize($input);
            $buffered = ob_get_clean();
            if ($buffered !== '') {
                $output = $buffered;
            } elseif (is_object($obj)) {
                $output = 'Deserialized: ' . get_class($obj);
            } else {
                $output = var_export($obj, true);
            }
            break;

        case '/unserialize-b64':
            $decoded = base64_decode($input, true);
            if ($decoded === false) {
                http_response_code(400);
                $error = 'Invalid base64 input';
                break;
            }
            ob_start();
            $obj = unserialize($decoded);
            $buffered = ob_get_clean();
            if ($buffered !== '') {
                $output = $buffered;
            } elseif (is_object($obj)) {
                $output = 'Deserialized: ' . get_class($obj);
            } else {
                $output = var_export($obj, true);
            }
            break;

        case '/phar':
            // Phar deserialization - file_exists/file_get_contents with phar:// wrapper
            if (str_starts_with($input, 'phar://')) {
                $result = @file_exists($input);
                if ($result) {
                    $output = 'file_exists: true';
                } else {
                    $output = 'file_exists: false';
                }
            } else {
                $error = 'Input must start with phar://';
            }
            break;

        default:
            http_response_code(404);
            $error = 'Unknown endpoint. Use /unserialize, /unserialize-b64, or /phar';
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
