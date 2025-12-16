import "pe"

rule MAL_Compromised_Cert_Quakbot_SSL_com_1730848A0A9AEB9F5968331E08D74236 {
   meta:
      description         = "Detects Quakbot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-22"
      version             = "1.0"

      hash                = "93a98b919aec23411ae62dba8d0d22f939da45dec19db2b4e7293124d8f1507f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SOFTWARE AGILITY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "17:30:84:8a:0a:9a:eb:9f:59:68:33:1e:08:d7:42:36"
      cert_thumbprint     = "50E22AA4B3B145FE1193EBBABED0637FA381FAC3"
      cert_valid_from     = "2023-11-22"
      cert_valid_to       = "2024-11-21"

      country             = "GB"
      state               = "???"
      locality            = "Ashby-De-La-Zouch"
      email               = "???"
      rdn_serial_number   = "08424580"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "17:30:84:8a:0a:9a:eb:9f:59:68:33:1e:08:d7:42:36"
      )
}
