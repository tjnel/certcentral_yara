import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_2A3A540A1CAFC491099CEFCDC539548F {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-23"
      version             = "1.0"

      hash                = "b339fed7fef43e82877fa606d19ae94b1393d75e09637066acc69777478a3799"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Wuxi Dainaide Network Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2a:3a:54:0a:1c:af:c4:91:09:9c:ef:cd:c5:39:54:8f"
      cert_thumbprint     = "151A8B902C8FA864B8D7DB95FFA2784E3DD4C4B7"
      cert_valid_from     = "2025-07-23"
      cert_valid_to       = "2026-07-01"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2a:3a:54:0a:1c:af:c4:91:09:9c:ef:cd:c5:39:54:8f"
      )
}
