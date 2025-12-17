import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_7F07AA1BB8A3B0183893B1AA {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-26"
      version             = "1.0"

      hash                = "7b13496fb45b51e821771d63bbd1d503f07710f676481ff34962b051283d8033"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "OMICARE JOINT STOCK COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:07:aa:1b:b8:a3:b0:18:38:93:b1:aa"
      cert_thumbprint     = "56FC98490B4845072947536B9E0AC121A37744E6"
      cert_valid_from     = "2024-09-26"
      cert_valid_to       = "2025-09-27"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "makedasalzbergneu79@gmail.com"
      rdn_serial_number   = "0108523661"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:07:aa:1b:b8:a3:b0:18:38:93:b1:aa"
      )
}
