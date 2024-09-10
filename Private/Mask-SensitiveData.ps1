function Mask-SensitiveData {
    param([string]$Message)
    return $Message -replace '\bpassword\b', '****'
}
