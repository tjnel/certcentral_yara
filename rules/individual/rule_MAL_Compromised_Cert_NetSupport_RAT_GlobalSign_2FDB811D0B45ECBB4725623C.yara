import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_2FDB811D0B45ECBB4725623C {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-06"
      version             = "1.0"

      hash                = "b7bd2a1969234d77ce7bdab808d77243e31899412e918c269b9f1b6748434be1"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "BCF SOFTWARE Sp. z o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2f:db:81:1d:0b:45:ec:bb:47:25:62:3c"
      cert_thumbprint     = "22164A50E1447B7B7B04A7B02087BB2035D9651D"
      cert_valid_from     = "2023-12-06"
      cert_valid_to       = "2024-12-06"

      country             = "PL"
      state               = "Opolskie"
      locality            = "Opole"
      email               = "admin@bcfsoftware.com"
      rdn_serial_number   = "0000634606"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2f:db:81:1d:0b:45:ec:bb:47:25:62:3c"
      )
}
