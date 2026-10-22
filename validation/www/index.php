<?php
// Minimal app for validation runs: uses sessions like most real PHP apps,
// so the server sends PHPSESSID and (with expose_php=On) X-Powered-By.
session_start();
header('Content-Type: text/html; charset=utf-8');
?><!doctype html><title>validation</title><p>ok</p>
