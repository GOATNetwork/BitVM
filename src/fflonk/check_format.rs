#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_check_format() {
        let script = script! {
            // C1
            { Fq::push_dec_montgomery("8993820735255461694205287896466659762517378169680151817278189507219986014273") }
            { Fq::push_dec_montgomery("20608602847008036615737932995836476570376266531776948091942386633580114403199") }
            { G1Affine::is_on_curve() }
            OP_VERIFY
            // C2
            { Fq::push_dec_montgomery("7381325072443970270370678023564870071058744625357849943766655609499175274412") }
            { Fq::push_dec_montgomery("15178578915928592705383893120230835636411008017183180871962629962483134367891") }
            { G1Affine::is_on_curve() }
            OP_VERIFY
            // W1
            { Fq::push_dec_montgomery("32650538602400348219903702316313439265244325226254563471430382441955222030") }
            { Fq::push_dec_montgomery("1102261574488401129043229793384018650738538286437537952751903719159654317199") }
            { G1Affine::is_on_curve() }
            OP_VERIFY
            // W2
            { Fq::push_dec_montgomery("11695827642347470645483614914520090101440686332033956264171712726147972703435") }
            { Fq::push_dec_montgomery("8930092616903485317239646434389939466400752538134075201209141980838088395614") }
            { G1Affine::is_on_curve() }
            OP_VERIFY
            // ql
            { Fr::push_dec_montgomery("4305584171954448775801758618991977283131671407134816099015723841718827300684") }
            { Fr::is_field() }
            OP_VERIFY
            // qr
            { Fr::push_dec_montgomery("12383383973686840675128398394454489421896122330596726461131121746926747341189") }
            { Fr::is_field() }
            OP_VERIFY
            // qm
            { Fr::push_dec_montgomery("84696450614978050680673343346456326547032107368333805624994614151289555853") }
            { Fr::is_field() }
            OP_VERIFY
            // qo
            { Fr::push_dec_montgomery("3940439340424631873531863239669720717811550024514867065774687720368464792371") }
            { Fr::is_field() }
            OP_VERIFY
            // qc
            { Fr::push_dec_montgomery("16961785810060156933739931986193776143069216115530808410139185289490606944009") }
            { Fr::is_field() }
            OP_VERIFY
            // s1
            { Fr::push_dec_montgomery("12474437127153975801320290893919924661315458586210754316226946498711086665749") }
            { Fr::is_field() }
            OP_VERIFY
            // s2
            { Fr::push_dec_montgomery("599434615255095347665395089945860172292558760398201299457995057871688253664") }
            { Fr::is_field() }
            OP_VERIFY
            // s3
            { Fr::push_dec_montgomery("16217604511932175446614838218599989473511950977205890369538297955449224727219") }
            { Fr::is_field() }
            OP_VERIFY
            // a
            { Fr::push_dec_montgomery("7211168621666826182043583595845418959530786367587156242724929610231435505336") }
            { Fr::is_field() }
            OP_VERIFY
            // b
            { Fr::push_dec_montgomery("848088075173937026388846472327431819307508078325359401333033359624801042") }
            { Fr::is_field() }
            OP_VERIFY
            // c
            { Fr::push_dec_montgomery("18963734392470978715233675860777231227480937309534365140504133190694875258320") }
            { Fr::is_field() }
            OP_VERIFY
            // z
            { Fr::push_dec_montgomery("2427313569771756255376235777000596702684056445296844486767054635200432142794") }
            { Fr::is_field() }
            OP_VERIFY
            // zw
            { Fr::push_dec_montgomery("8690328511114991742730387856275843464438882369629727414507275814599493141660") }
            { Fr::is_field() }
            OP_VERIFY
            // t1w
            { Fr::push_dec_montgomery("20786626696833495453279531623626288211765949258916047124642669459480728122908") }
            { Fr::is_field() }
            OP_VERIFY
            // t2w
            { Fr::push_dec_montgomery("12092130080251498309415337127155404037148503145602589831662396526189421234148") }
            { Fr::is_field() }
            OP_VERIFY
            // inv
            { Fr::push_dec_montgomery("21247383512588455895834686692756529012394058115069710447132959660051940541361") }
            { Fr::is_field() }
        };
        println!("fflonk.check_format = {} bytes", script.len());
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
