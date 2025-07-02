# NFC Services Library

A comprehensive Flutter/Dart package for secure NFC operations with MIFARE Plus and DESFire cards using AES-128 encryption.

[![Flutter](https://img.shields.io/badge/Flutter-3.7.2+-blue.svg)](https://flutter.dev/)
[![Dart](https://img.shields.io/badge/Dart-3.0+-blue.svg)](https://dart.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🚀 Features

- **🔐 Secure Authentication**: AES-128 encryption for all card communications
- **📱 Multi-Card Support**: MIFARE Plus and DESFire card operations
- **🛡️ Type-Safe Results**: Sealed classes for comprehensive error handling
- **🔧 Debug Support**: Detailed logging for development and troubleshooting
- **📊 Data Conversion**: Built-in utilities for binary, hex, ASCII, and decimal formats
- **🌐 Cross-Platform**: Android 5.0+ and iOS 11.0+ support

## 📋 Supported NFC Standards

| Standard | Card Type | Authentication | Data Access |
|----------|-----------|----------------|-------------|
| ISO 14443 Type A | MIFARE Plus | AES-128 | Sectors 1-39, Blocks 0-14 |
| ISO 14443 Type A | DESFire | AES-128 | Applications & Files |
| ISO 7816 | Generic | Platform-dependent | Limited |

## 📦 Installation

Add this to your package's `pubspec.yaml` file:

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_nfc_kit: ^3.3.1
  convert: ^3.0.1
  encrypt: ^5.0.1
  pointycastle: ^3.9.1
  shared_preferences: ^2.2.2
```

Then run:

```bash
flutter pub get
```

## 🚀 Quick Start

### 1. Import the Library

```dart
import 'package:roger_nfc_services/nfc_services/desfire_services.dart';
import 'package:roger_nfc_services/nfc_services/plus_services.dart';
import 'package:roger_nfc_services/nfc_services/shared/nfc_utilities.dart';
```

### 2. Check NFC Availability

```dart
final nfcStatus = await isNfcAvailable();
if (nfcStatus.isSuccess) {
  // NFC is available, proceed with operations
} else {
  print("NFC Error: ${nfcStatus.message}");
}
```

### 3. Read DESFire Card

```dart
final desfireService = DesfireNfcServices(debugMode: true);

final result = await desfireService.readDesfire(
  applicationId: "123456",
  fileId: "01",
  keyNumber: "00",
  authKey: "00112233445566778899AABBCCDDEEFF",
);

if (result.isSuccess) {
  print("DESFire Data: ${result.data}");
} else {
  print("Error: ${result.errorCode?.description}");
}
```

### 4. Read MIFARE Plus Card

```dart
final plusService = PlusServices(debugMode: true);

final result = await plusService.readPlus(
  sector: 1,
  block: 0,
  keyType: KeyType.keyA,
  keyHex: "00112233445566778899AABBCCDDEEFF",
);

if (result.isSuccess) {
  print("Plus Data: ${result.data}");
} else {
  print("Error: ${result.errorCode?.description}");
}
```

## 🏗️ Architecture

```
lib/nfc_services/
├── desfire_services.dart      # DESFire card operations
├── plus_services.dart         # MIFARE Plus card operations
└── shared/
    ├── nfc_utilities.dart     # Core NFC functionality
    ├── crypto_utilities.dart  # Cryptographic operations
    └── binary_conversion.dart # Data format conversion
```

## 📱 Platform Setup

### Android

Add to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-feature 
    android:name="android.hardware.nfc" 
    android:required="true" />
```

### iOS

Add to `ios/Runner/Info.plist`:

```xml
<key>NFCReaderUsageDescription</key>
<string>This app uses NFC to read MIFARE Plus and DESFire cards</string>

<key>com.apple.developer.nfc.readersession.formats</key>
<array>
    <string>NDEF</string>
    <string>TAG</string>
</array>
```

Add NFC capability in Xcode under "Signing & Capabilities".

## 🔧 Configuration Options

### DESFire Service

```dart
final service = DesfireNfcServices(
  debugMode: true,                          // Enable debug logging
  timeout: 7,                              // Operation timeout (seconds)
  alertMessage: "Scan your DESFire card",  // User prompt message
  multipleTagMessage: "Multiple tags found!" // Multiple tag message
);
```

### MIFARE Plus Service

```dart
final service = PlusServices(
  debugMode: true,                            // Enable debug logging
  timeout: 10,                               // Operation timeout (seconds)
  alertMessage: "Scan your MIFARE Plus card", // User prompt message
  multipleTagMessage: "Multiple tags found!"  // Multiple tag message
);
```

## 🛠️ Data Processing

Convert card data to different formats:

```dart
import 'package:roger_nfc_services/nfc_services/shared/binary_conversion.dart';

// Convert hex data to different formats
final hexData = "48656C6C6F"; // "Hello" in hex
final binary = BinaryConversion.toBinary(hexData, 0, 4);
final ascii = BinaryConversion.toASCII(hexData, 0, 4);
final decimal = BinaryConversion.toDecimal(hexData, 0, 4);

print('Binary: $binary');   // 01001000 01100101 01101100 01101100 01101111
print('ASCII: $ascii');     // Hello
print('Decimal: $decimal'); // 72 101 108 108 111
```

## ⚠️ Error Handling

The library uses sealed classes for type-safe error handling:

```dart
final result = await service.readCard(...);

if (result.isSuccess) {
  // Safe to access result.data
  processData(result.data!);
} else {
  // Handle specific error types
  switch (result.errorCode) {
    case DesfireErrorCode.authenticationFailed:
      handleAuthError();
      break;
    case DesfireErrorCode.cardConnectionLost:
      handleConnectionError();
      break;
    default:
      handleGenericError(result.errorCode?.description);
  }
}
```

## 🐛 Common Issues

### Authentication Failed
- Verify the authentication key is exactly 32 hex characters
- Check that the key number/type matches the card configuration
- Ensure the application/sector exists on the card

### Card Connection Lost
- Instruct users to keep the card steady during operations
- Use shorter timeout values for better reliability
- Check for interference from other NFC devices

### NFC Not Available
- Verify NFC permissions are granted
- Check that NFC is enabled in device settings
- Ensure the device supports NFC hardware

## 📚 Documentation

For comprehensive documentation including detailed API reference, advanced usage examples, and troubleshooting guide, see:

**[📖 Complete Documentation](nfc_services.md)**

## 🧪 Example App

Check out the example application in the `lib/example_use/` directory for complete implementation examples:

- `desfire_screen.dart` - DESFire card reading example
- `plus_screen.dart` - MIFARE Plus card reading example

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | January 2025 | Initial release with DESFire and MIFARE Plus support |
| 0.1.0 | December 2024 | Development version |

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Complete User Manual](nfc_services.md)
- **Issues**: Report bugs and feature requests through GitHub Issues
- **Discussions**: Join project discussions for community support

## 🏷️ Keywords

`flutter` `dart` `nfc` `mifare` `desfire` `aes` `encryption` `authentication` `mobile` `android` `ios` `card-reader` `rfid` `near-field-communication`

---

**Built with ❤️ for the Flutter community**
