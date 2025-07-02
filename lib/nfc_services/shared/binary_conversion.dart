/// Utility class for converting binary data between different formats
/// 
/// This class provides methods to convert hex strings to binary, hex, and ASCII formats
/// with support for byte range selection and byte reversal.
class BinaryConversion {
  /// Reverses a hex string by bytes (2 characters per byte)
  /// 
  /// [input] the hex string to reverse
  /// 
  /// Throws [ArgumentError] if input is empty or invalid.
  /// Returns the reversed hex string with bytes in reverse order.
  /// 
  /// Example: "12345678" becomes "78563412"
  static String _reverseHexBytes(String input) {
    if (input.isEmpty) return input;
    
    final bytes = RegExp(r'..').allMatches(input).map((m) => m.group(0)!).toList();
    return bytes.reversed.join();
  }

  /// Converts a hex string to a spaced binary string for a byte range.
  /// 
  /// [data] the hex string to convert
  /// [firstBytePosition] the starting byte position (0-based)
  /// [lastBytePosition] the ending byte position (0-based)
  /// 
  /// If firstBytePosition > lastBytePosition, bytes are reversed.
  /// Throws [ArgumentError] if input is invalid or positions are out of range.
  /// 
  /// Returns a binary string with spaces between bytes.
  /// 
  /// Example: toBinary("12345678", 0, 1) returns "00010010 00110100"
  static String toBinary(String data, int firstBytePosition, int lastBytePosition) {
    _validateInput(data, firstBytePosition, lastBytePosition);
    
    String processedData = data;
    if (firstBytePosition > lastBytePosition) {
      processedData = _reverseHexBytes(data);
    }
    
    final startIndex = firstBytePosition * 2;
    final endIndex = (lastBytePosition + 1) * 2;
    final targetData = processedData.substring(startIndex, endIndex);
    
    return targetData.replaceAllMapped(
      RegExp(r'..'),
      (match) => '${int.parse(match.group(0)!, radix: 16).toRadixString(2).padLeft(8, '0')} ',
    ).trim();
  }

  /// Converts a hex string to a spaced uppercase hex string for a byte range.
  /// 
  /// [data] the hex string to convert
  /// [firstBytePosition] the starting byte position (0-based)
  /// [lastBytePosition] the ending byte position (0-based)
  /// 
  /// If firstBytePosition > lastBytePosition, bytes are reversed.
  /// Throws [ArgumentError] if input is invalid or positions are out of range.
  /// 
  /// Returns a hex string with spaces between bytes in uppercase format.
  /// 
  /// Example: toHex("12345678", 0, 1) returns "12 34"
  static String toHex(String data, int firstBytePosition, int lastBytePosition) {
    _validateInput(data, firstBytePosition, lastBytePosition);
    
    String processedData = data;
    if (firstBytePosition > lastBytePosition) {
      processedData = _reverseHexBytes(data);
    }
    
    final startIndex = firstBytePosition * 2;
    final endIndex = (lastBytePosition + 1) * 2;
    final targetData = processedData.substring(startIndex, endIndex);
    
    return targetData.replaceAllMapped(
      RegExp(r'..'),
      (match) => '${match.group(0)!.toUpperCase()} ',
    ).trim();
  }

  /// Converts a hex string to an ASCII string for a byte range.
  /// 
  /// [data] the hex string to convert
  /// [firstBytePosition] the starting byte position (0-based)
  /// [lastBytePosition] the ending byte position (0-based)
  /// 
  /// If firstBytePosition > lastBytePosition, bytes are reversed.
  /// Throws [ArgumentError] if input is invalid or positions are out of range.
  /// 
  /// Returns an ASCII string representation with non-printable characters replaced by dots.
  /// 
  /// Example: toASCII("48656C6C6F", 0, 4) returns "Hello"
  static String toASCII(String data, int firstBytePosition, int lastBytePosition) {
    _validateInput(data, firstBytePosition, lastBytePosition);
    
    String processedData = data;
    if (firstBytePosition > lastBytePosition) {
      processedData = _reverseHexBytes(data);
    }
    
    final startIndex = firstBytePosition * 2;
    final endIndex = (lastBytePosition + 1) * 2;
    final targetData = processedData.substring(startIndex, endIndex);
    
    return targetData.replaceAllMapped(
      RegExp(r'..'),
      (match) {
        final charCode = int.parse(match.group(0)!, radix: 16);
        // Only include printable ASCII characters (32-126)
        return charCode >= 32 && charCode <= 126 ? String.fromCharCode(charCode) : '.';
      },
    );
  }

  /// Converts a hex string to a decimal string for a byte range.
  /// 
  /// [data] the hex string to convert
  /// [firstBytePosition] the starting byte position (0-based)
  /// [lastBytePosition] the ending byte position (0-based)
  /// 
  /// If firstBytePosition > lastBytePosition, bytes are reversed.
  /// Throws [ArgumentError] if input is invalid or positions are out of range.
  /// 
  /// Returns a decimal string with spaces between bytes.
  /// 
  /// Example: toDecimal("12345678", 0, 1) returns "18 52"
  static String toDecimal(String data, int firstBytePosition, int lastBytePosition) {
    _validateInput(data, firstBytePosition, lastBytePosition);
    
    String processedData = data;
    if (firstBytePosition > lastBytePosition) {
      processedData = _reverseHexBytes(data);
    }
    
    final startIndex = firstBytePosition * 2;
    final endIndex = (lastBytePosition + 1) * 2;
    final targetData = processedData.substring(startIndex, endIndex);
    
    return targetData.replaceAllMapped(
      RegExp(r'..'),
      (match) => '${int.parse(match.group(0)!, radix: 16)} ',
    ).trim();
  }

  /// Extracts a specific byte from a hex string.
  /// 
  /// [data] the hex string
  /// [bytePosition] the byte position to extract (0-based)
  /// 
  /// Throws [ArgumentError] if input is invalid or position is out of range.
  /// Returns the byte as a 2-character hex string.
  /// 
  /// Example: getByte("12345678", 1) returns "34"
  static String getByte(String data, int bytePosition) {
    _validateInput(data, bytePosition, bytePosition);
    return data.substring(bytePosition * 2, (bytePosition + 1) * 2);
  }

  /// Gets the length of data in bytes.
  /// 
  /// [data] the hex string
  /// 
  /// Throws [ArgumentError] if hex string is empty or has odd length.
  /// Returns the number of bytes in the hex string.
  /// 
  /// Example: getByteLength("12345678") returns 4
  static int getByteLength(String data) {
    if (data.isEmpty || data.length % 2 != 0) {
      throw ArgumentError('Hex string must be non-empty and even length.');
    }
    return data.length ~/ 2;
  }

  /// Checks if a string is a valid hex string.
  /// 
  /// [data] the string to validate
  /// 
  /// Returns true if the string is a valid hex string (non-empty, even length, hex characters only).
  /// 
  /// Example: isValidHex("12345678") returns true
  /// Example: isValidHex("1234567") returns false (odd length)
  /// Example: isValidHex("1234567G") returns false (invalid character)
  static bool isValidHex(String data) {
    if (data.isEmpty || data.length % 2 != 0) return false;
    return RegExp(r'^[0-9A-Fa-f]+$').hasMatch(data);
  }

  /// Validates input for conversion methods.
  /// 
  /// [data] the hex string to validate
  /// [firstBytePosition] the starting byte position
  /// [lastBytePosition] the ending byte position
  /// 
  /// Throws [ArgumentError] if validation fails (empty data, odd length, invalid characters, out of range positions).
  /// 
  /// This method ensures all conversion methods receive valid input parameters.
  static void _validateInput(String data, int firstBytePosition, int lastBytePosition) {
    if (data.isEmpty) {
      throw ArgumentError('Hex string cannot be empty.');
    }
    
    if (data.length % 2 != 0) {
      throw ArgumentError('Hex string must have even length (got ${data.length}).');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(data)) {
      throw ArgumentError('Hex string contains invalid characters.');
    }
    
    final totalBytes = data.length ~/ 2;
    
    if (firstBytePosition < 0) {
      throw RangeError('First byte position cannot be negative (got $firstBytePosition).');
    }
    
    if (lastBytePosition < 0) {
      throw RangeError('Last byte position cannot be negative (got $lastBytePosition).');
    }
    
    if (firstBytePosition >= totalBytes) {
      throw RangeError('First byte position out of range (got $firstBytePosition, max ${totalBytes - 1}).');
    }
    
    if (lastBytePosition >= totalBytes) {
      throw RangeError('Last byte position out of range (got $lastBytePosition, max ${totalBytes - 1}).');
    }
  }
}