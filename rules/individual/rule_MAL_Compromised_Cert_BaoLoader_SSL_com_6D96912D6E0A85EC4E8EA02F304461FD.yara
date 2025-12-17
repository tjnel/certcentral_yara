import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_6D96912D6E0A85EC4E8EA02F304461FD {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-11"
      version             = "1.0"

      hash                = "3276154a7f2ea64e43cf6dbec33bfb20ee0d46b2ca03d5d0c7f51ec803f7101d"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Astral Media Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:96:91:2d:6e:0a:85:ec:4e:8e:a0:2f:30:44:61:fd"
      cert_thumbprint     = "4B8A14727083C59DAC9E3300F64B045BB21AD601"
      cert_valid_from     = "2023-04-11"
      cert_valid_to       = "2026-04-10"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704413"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:96:91:2d:6e:0a:85:ec:4e:8e:a0:2f:30:44:61:fd"
      )
}
