import "pe"

rule MAL_Compromised_Cert_DarkGate_SSL_com_762BE19F15589A12D79577BEB7DD421E {
   meta:
      description         = "Detects DarkGate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-12"
      version             = "1.0"

      hash                = "4fe8bbc88d7a8cc0eec24bd74951f1f00b5127e3899ae53de8dabd6ff417e6db"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "KDL CENTRAL LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "76:2b:e1:9f:15:58:9a:12:d7:95:77:be:b7:dd:42:1e"
      cert_thumbprint     = "2a279b16102e3dd8989ab8ec37c63eef6780e05b38864a427a50ca0ddeff70c1"
      cert_valid_from     = "2024-12-12"
      cert_valid_to       = "2025-12-12"

      country             = "GB"
      state               = "???"
      locality            = "Bracknell"
      email               = "???"
      rdn_serial_number   = "09105940"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "76:2b:e1:9f:15:58:9a:12:d7:95:77:be:b7:dd:42:1e"
      )
}
