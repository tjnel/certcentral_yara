import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_2352CE593F487633E8C7C819FABF9C74 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-14"
      version             = "1.0"

      hash                = "e38b838995dfe3df7419264d3a02877fe8239e691b2bcd18b843afe8c7f9961e"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"ТОРГОВИЙ ДІМ КБ СТІЛ\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:52:ce:59:3f:48:76:33:e8:c7:c8:19:fa:bf:9c:74"
      cert_thumbprint     = "AC0380618B3ABA28892F886062ADFF1F554C5B1A"
      cert_valid_from     = "2023-08-14"
      cert_valid_to       = "2024-08-13"

      country             = "UA"
      state               = "Дніпропетровська"
      locality            = "Нікополь"
      email               = "???"
      rdn_serial_number   = "44326353"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:52:ce:59:3f:48:76:33:e8:c7:c8:19:fa:bf:9c:74"
      )
}
