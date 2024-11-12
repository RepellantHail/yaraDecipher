rule Detect_RC4_Decryption_Success
{
    meta:
        description = "Detects potential RC4 decrypted content by identifying common text patterns or file markers"
        author = "Your Name"
        date = "2024-11-10"
    
    strings:
        // ASCII or UTF-8 readable text patterns (e.g., common English words or phrases)
        $text_pattern1 = "int main"          // Common code snippet if it's plaintext code
        $text_pattern2 = "include"           // Common in C++ code
        $text_pattern3 = "return"            // Likely in many code files
        $text_pattern4 = "std::"             // Common in C++ standard library usage

        // Any specific headers or other indicators you expect (update as needed)
        $header_pattern = { 23 69 6E 63 6C 75 64 65 3C } // Example for '#include<'
    
    condition:
        any of ($text_pattern*) or $header_pattern
}
