import "pe"

rule MAL_Compromised_Cert_ZeroDayTraffer_SSL_com_39D6C425AB7C43EA309C2D64F62E86D6 {
   meta:
      description         = "Detects ZeroDayTraffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-15"
      version             = "1.0"

      hash                = "890f619b890b0a30d5f88a7acb523b670eea902683d9233f1d7f8d08b64500b8"
      malware             = "ZeroDayTraffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THE PACK (Shanghai) Corp."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "39:d6:c4:25:ab:7c:43:ea:30:9c:2d:64:f6:2e:86:d6"
      cert_thumbprint     = "85F8A46CA3002846015A6D3048BB9058B844D63E"
      cert_valid_from     = "2025-02-15"
      cert_valid_to       = "2026-02-11"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "913100007862663014"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "39:d6:c4:25:ab:7c:43:ea:30:9c:2d:64:f6:2e:86:d6"
      )
}
