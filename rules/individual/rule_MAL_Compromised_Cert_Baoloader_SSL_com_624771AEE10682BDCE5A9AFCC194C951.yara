import "pe"

rule MAL_Compromised_Cert_Baoloader_SSL_com_624771AEE10682BDCE5A9AFCC194C951 {
   meta:
      description         = "Detects Baoloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-15"
      version             = "1.0"

      hash                = "d54b18f88cb3ee55b6175d5fb46ba395897a44dad543b0a95105b910b3318057"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Digital Promotions Sdn. Bhd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "62:47:71:ae:e1:06:82:bd:ce:5a:9a:fc:c1:94:c9:51"
      cert_thumbprint     = "DEC05EF328D74480A8955C61458977D3358A1D5A"
      cert_valid_from     = "2023-06-15"
      cert_valid_to       = "2026-06-14"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "202301011511"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "62:47:71:ae:e1:06:82:bd:ce:5a:9a:fc:c1:94:c9:51"
      )
}
