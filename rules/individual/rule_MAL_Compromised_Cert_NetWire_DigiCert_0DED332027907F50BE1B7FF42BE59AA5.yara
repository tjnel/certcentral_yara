import "pe"

rule MAL_Compromised_Cert_NetWire_DigiCert_0DED332027907F50BE1B7FF42BE59AA5 {
   meta:
      description         = "Detects NetWire with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-28"
      version             = "1.0"

      hash                = "17a3a47fee308ff270af546a193a78a7328f43a1fa3bdaee5fdbd96f4bf6cbd4"
      malware             = "NetWire"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ORANGE VIEW LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0d:ed:33:20:27:90:7f:50:be:1b:7f:f4:2b:e5:9a:a5"
      cert_thumbprint     = "7A08FEAD84E1823418798EEE3DA3B49B6115FA71"
      cert_valid_from     = "2020-11-28"
      cert_valid_to       = "2023-10-22"

      country             = "HK"
      state               = "???"
      locality            = "Kowloon"
      email               = "???"
      rdn_serial_number   = "2770852"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0d:ed:33:20:27:90:7f:50:be:1b:7f:f4:2b:e5:9a:a5"
      )
}
