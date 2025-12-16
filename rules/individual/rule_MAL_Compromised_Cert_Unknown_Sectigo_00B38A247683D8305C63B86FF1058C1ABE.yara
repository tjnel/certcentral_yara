import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00B38A247683D8305C63B86FF1058C1ABE {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-16"
      version             = "1.0"

      hash                = "815f48f859ead76effaa4b8ad2a1cd36b563003cbec56c5f655732e24bd20647"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yongji Xiaodong Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b3:8a:24:76:83:d8:30:5c:63:b8:6f:f1:05:8c:1a:be"
      cert_thumbprint     = "512698469C15742F325AF0D13E1E9386DDCB91F3"
      cert_valid_from     = "2025-09-16"
      cert_valid_to       = "2026-09-16"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b3:8a:24:76:83:d8:30:5c:63:b8:6f:f1:05:8c:1a:be"
      )
}
