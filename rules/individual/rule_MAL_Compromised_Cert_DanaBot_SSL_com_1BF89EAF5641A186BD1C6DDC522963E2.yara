import "pe"

rule MAL_Compromised_Cert_DanaBot_SSL_com_1BF89EAF5641A186BD1C6DDC522963E2 {
   meta:
      description         = "Detects DanaBot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-15"
      version             = "1.0"

      hash                = "91b170eb7a731597174b7a5baaf119534a99eb7f833b7101728967d2deb93a35"
      malware             = "DanaBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Yizhan Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1b:f8:9e:af:56:41:a1:86:bd:1c:6d:dc:52:29:63:e2"
      cert_thumbprint     = "815C03862D6F134C1742FE8F8E6776AD42CB0AEE"
      cert_valid_from     = "2024-04-15"
      cert_valid_to       = "2025-04-15"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA5ATCPC3N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1b:f8:9e:af:56:41:a1:86:bd:1c:6d:dc:52:29:63:e2"
      )
}
