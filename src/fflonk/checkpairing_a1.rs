#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Projective;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_checkpairing_a1() {
        let script = script! {
            // push F, E, J, W2
            { Fq::push_dec_montgomery("10827057179016943379099096512257711381208881258335395636699788359889105647796") }
            { Fq::push_dec_montgomery("15908485457276609870374048914742234656312588226903176268190825086381552148601") }
            { Fq::push_dec_montgomery("10704903381596808863042656941383257630189957941456629442401491652278045385710") }

            { Fq::push_dec_montgomery("10905825615646575916826598897124608361270584984190374057529352166783343482862") }
            { Fq::push_dec_montgomery("19290909793509893735943189519527824156597590461000288988451227768509803549366") }
            { Fq::push_dec_montgomery("10334981607594421347972269000738063023881743479366183631046354259553646162574") }

            { Fq::push_dec_montgomery("2959562071167086018427906252728568621973040394868315776950851582459669551081") }
            { Fq::push_dec_montgomery("5248835691815263544471788309691308785423871173394577194626050104765380585421") }
            { Fq::push_dec_montgomery("19277062899702791882368245424983329716198384271778017207570439921049817477033") }

            { Fq::push_dec_montgomery("11695827642347470645483614914520090101440686332033956264171712726147972703435") }
            { Fq::push_dec_montgomery("8930092616903485317239646434389939466400752538134075201209141980838088395614") }
            { Fq::push_dec_montgomery("1") }

            // push y
            { Fr::push_dec_montgomery("6824639836122392703554190210911349683223362245243195922653951653214183338070") }

            { G1Projective::scalar_mul() }
            { G1Projective::roll(3) }
            { G1Projective::add() }

            { G1Projective::roll(2) }
            { G1Projective::neg() }
            { G1Projective::add() }

            { G1Projective::roll(1) }
            { G1Projective::neg() }
            { G1Projective::add() }

            { Fq::push_dec_montgomery("21025932300722401404248737517866966587837387913191004025854702115722286998035") }
            { Fq::push_dec_montgomery("5748766770337880144484917096976043621609890780406924686031233755006782215858") }
            { Fq::push_dec_montgomery("18747233771850556311508953762939425433543524671221692065979284256379095132287") }

            { G1Projective::equalverify() }
            OP_TRUE
        };

        println!("fflonk.checkpairing_a = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
