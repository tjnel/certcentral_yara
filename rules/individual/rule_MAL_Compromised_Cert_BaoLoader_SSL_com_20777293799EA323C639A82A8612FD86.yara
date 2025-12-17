import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_20777293799EA323C639A82A8612FD86 {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-22"
      version             = "1.0"

      hash                = "4c57be15f581c8ad23b416d7036b89fcfa37a5544e8e53163c0488f5e9af9073"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Digital Promotions Sdn. Bhd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "20:77:72:93:79:9e:a3:23:c6:39:a8:2a:86:12:fd:86"
      cert_thumbprint     = "F0E0C22F6150929994FA4E5C1A7B0644A5768FEF"
      cert_valid_from     = "2025-07-22"
      cert_valid_to       = "2026-06-14"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "20:77:72:93:79:9e:a3:23:c6:39:a8:2a:86:12:fd:86"
      )
}
