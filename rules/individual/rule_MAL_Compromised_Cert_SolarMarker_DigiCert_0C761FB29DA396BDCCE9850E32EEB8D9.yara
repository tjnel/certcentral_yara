import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0C761FB29DA396BDCCE9850E32EEB8D9 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-02"
      version             = "1.0"

      hash                = "6c59f4f268f1ce1d85cdf9169e81464bb950ec572ea1e3ab9cc4ff4a75589435"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Table Ronde 1155 Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:76:1f:b2:9d:a3:96:bd:cc:e9:85:0e:32:ee:b8:d9"
      cert_thumbprint     = "94A71D5BE515AB0F700B2F0DBFFD9175DAFFE450"
      cert_valid_from     = "2024-05-02"
      cert_valid_to       = "2025-05-04"

      country             = "CA"
      state               = "Quebec"
      locality            = "Saint- Laurent"
      email               = "???"
      rdn_serial_number   = "1292530-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:76:1f:b2:9d:a3:96:bd:cc:e9:85:0e:32:ee:b8:d9"
      )
}
