import "pe"

rule MAL_Compromised_Cert_Baoloader_GlobalSign_582C3A4B9934B7EC1028B638 {
   meta:
      description         = "Detects Baoloader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-09"
      version             = "1.0"

      hash                = "fde67ba523b2c1e517d679ad4eaf87925c6bbf2f171b9212462dc9a855faa34b"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Echo Infini Sdn. Bhd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "58:2c:3a:4b:99:34:b7:ec:10:28:b6:38"
      cert_thumbprint     = "A2278EB6A438DC528F3EBFEB238028C474401BEF"
      cert_valid_from     = "2024-12-09"
      cert_valid_to       = "2026-12-10"

      country             = "MY"
      state               = "Johor"
      locality            = "Johor Bahru"
      email               = "operation@echoinfini.net"
      rdn_serial_number   = "1577033-U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "58:2c:3a:4b:99:34:b7:ec:10:28:b6:38"
      )
}
