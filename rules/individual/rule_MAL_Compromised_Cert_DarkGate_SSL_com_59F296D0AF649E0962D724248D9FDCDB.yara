import "pe"

rule MAL_Compromised_Cert_DarkGate_SSL_com_59F296D0AF649E0962D724248D9FDCDB {
   meta:
      description         = "Detects DarkGate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-28"
      version             = "1.0"

      hash                = "080cee402e284222cef8a3ff10b94a0b364feb5b9047f2babcb6ea0d1e331932"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "MK ZN s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "59:f2:96:d0:af:64:9e:09:62:d7:24:24:8d:9f:dc:db"
      cert_thumbprint     = "0D762B095F6F2BA2DBEB00C5B8E9C93294FAD66F"
      cert_valid_from     = "2023-09-28"
      cert_valid_to       = "2024-09-27"

      country             = "CZ"
      state               = "???"
      locality            = "Brno"
      email               = "???"
      rdn_serial_number   = "049 95 287"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "59:f2:96:d0:af:64:9e:09:62:d7:24:24:8d:9f:dc:db"
      )
}
