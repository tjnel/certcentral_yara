import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_46D8111B3080ACFE06AB32EBB3572A44 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-25"
      version             = "1.0"

      hash                = "9e503796d957d0f00e1d4102a4b7690f679219fb609de4b3343612bb939b1c24"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Appchefs Software Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "46:d8:11:1b:30:80:ac:fe:06:ab:32:eb:b3:57:2a:44"
      cert_thumbprint     = "4D4299F14DC4EE5B58DFE20A5F73F467185A0403"
      cert_valid_from     = "2024-04-25"
      cert_valid_to       = "2025-04-25"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "46:d8:11:1b:30:80:ac:fe:06:ab:32:eb:b3:57:2a:44"
      )
}
