import "pe"

rule MAL_Compromised_Cert_DarkGate_SSL_com_1D9D011E1B8372FF5B4ED47D1501A4AB {
   meta:
      description         = "Detects DarkGate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-15"
      version             = "1.0"

      hash                = "22f34cc0b56ea1709b3af15b41b43fc40fca2b77debb8400108d3f517ee2ed4a"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Catapultk Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1d:9d:01:1e:1b:83:72:ff:5b:4e:d4:7d:15:01:a4:ab"
      cert_thumbprint     = "40DB4382B4FCA6706113812737D12828A0BF18D9"
      cert_valid_from     = "2024-04-15"
      cert_valid_to       = "2025-04-15"

      country             = "GB"
      state               = "???"
      locality            = "Boston Spa"
      email               = "???"
      rdn_serial_number   = "08618980"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1d:9d:01:1e:1b:83:72:ff:5b:4e:d4:7d:15:01:a4:ab"
      )
}
