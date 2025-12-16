import "pe"

rule MAL_Compromised_Cert_ResidentialProxyInstaller_GoGetSSL_0B902CA1B6CA4C44CF6D10B8BBAD35B2 {
   meta:
      description         = "Detects ResidentialProxyInstaller with compromised cert (GoGetSSL)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-27"
      version             = "1.0"

      hash                = "157ddc5859b7950e7c44573a06837aae1fd86379e7b27fdd0d14617bc7947b4f"
      malware             = "ResidentialProxyInstaller"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Agora International Agency Bilisim Hizmetleri Limited Sirketi"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0b:90:2c:a1:b6:ca:4c:44:cf:6d:10:b8:bb:ad:35:b2"
      cert_thumbprint     = "e4a3e1a46b794116f5e1427fa7ff4b0e2bde6983"
      cert_valid_from     = "2024-06-27"
      cert_valid_to       = "2027-06-26"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Kadıköy"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0b:90:2c:a1:b6:ca:4c:44:cf:6d:10:b8:bb:ad:35:b2"
      )
}
