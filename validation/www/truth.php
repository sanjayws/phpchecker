<?php
// Ground truth for the validation harness: the exact runtime version and SAPI.
header('Content-Type: application/json');
echo json_encode(['version' => PHP_VERSION, 'sapi' => PHP_SAPI, 'expose_php' => ini_get('expose_php')]);
