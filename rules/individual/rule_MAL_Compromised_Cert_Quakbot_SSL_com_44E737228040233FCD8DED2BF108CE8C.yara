import "pe"

rule MAL_Compromised_Cert_Quakbot_SSL_com_44E737228040233FCD8DED2BF108CE8C {
   meta:
      description         = "Detects Quakbot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-26"
      version             = "1.0"

      hash                = "8db0b8f45f726a963b34410c74194e0b40f6720561731e8242ee60a8a7d7e3ce"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Ken Friedman AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "44:e7:37:22:80:40:23:3f:cd:8d:ed:2b:f1:08:ce:8c"
      cert_thumbprint     = "BB296138FB75F5CEB45E36B85A8DF7CC82C6364C"
      cert_valid_from     = "2023-12-26"
      cert_valid_to       = "2024-12-25"

      country             = "SE"
      state               = "Kalmar County"
      locality            = "Kalmar"
      email               = "???"
      rdn_serial_number   = "556982-0771"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "44:e7:37:22:80:40:23:3f:cd:8d:ed:2b:f1:08:ce:8c"
      )
}
