import { useEffect, useState } from "react";
import { Card } from "../components/Card";
import { Tabs } from "../components/Tabs";
import type { TabDef } from "../components/Tabs";
import { Staking } from "./Staking";
import { RewardHistory } from "./RewardHistory";
import { PoolDirectory } from "./PoolDirectory";

type Tab = "delegation" | "rewards" | "pools";

const TABS: readonly TabDef<Tab>[] = [
  { key: "delegation", label: "Delegation" },
  { key: "rewards", label: "Rewards" },
  { key: "pools", label: "Pools" },
];

interface StakeProps {
  network?: string;
  isHardware?: boolean;
  walletId?: string;
  // Whether this wallet on this node can actually submit a delegation. Rewards
  // and the pool directory are node-local reads available to any active wallet,
  // so the screen stays reachable and only the Delegation tab explains itself.
  canDelegate?: boolean;
  // Which tab to open on. Lets the legacy #/rewards and #/pools routes land
  // where the user expected rather than dumping them on Delegation.
  initialTab?: Tab;
}

/**
 * Stake is the single destination for everything staking.
 *
 * Delegation, reward history and the pool directory were three separate
 * top-level screens answering one question — what is my ADA doing and where
 * should it go. Worse, they did not connect: the directory's own help text
 * told you to copy a pool ID and paste it into the delegation screen, with the
 * clipboard as the integration layer between two halves of one task.
 *
 * Here they are tabs of one screen, and choosing a pool in the directory hands
 * that pool straight to the delegation form.
 */
export function Stake({
  network = "preview",
  isHardware,
  walletId,
  canDelegate = true,
  initialTab = "delegation",
}: StakeProps = {}) {
  const [tab, setTab] = useState<Tab>(initialTab);

  // The route can change while this screen stays mounted (#/pools -> #/rewards
  // is the same component in the same place), and initial state would ignore
  // that, leaving the user on whichever tab they first arrived at.
  useEffect(() => {
    setTab(initialTab);
  }, [initialTab]);

  // The delegation draft's pool ID lives here rather than inside Staking so it
  // survives a tab switch — the whole point of merging these is that you can
  // browse Pools and come back without losing what you had typed.
  const [poolId, setPoolId] = useState("");
  // Set when the user picks a pool from the directory. Switching tabs unmounts
  // the delegation screen, so this is read at its next mount rather than
  // signalled to a live component -- and cleared once taken, so coming back to
  // the tab later opens on the status panel as usual.
  const [composeIntent, setComposeIntent] = useState(false);

  function handleDelegate(id: string) {
    setPoolId(id);
    setComposeIntent(true);
    setTab("delegation");
  }

  return (
    <div className="stake">
      <Tabs id="stake" tabs={TABS} active={tab} onSelect={setTab}>
        {(key) => {
          switch (key) {
            case "delegation":
              if (!canDelegate) {
                return (
                  <Card title="Delegation">
                    <p className="helper-text">
                      This wallet cannot submit a delegation. Delegating needs a
                      fully synced node and a wallet that can sign a certificate
                      — a watch-only wallet, or a hardware wallet whose device
                      does not sign certificates, can still browse pools and
                      review rewards here.
                    </p>
                  </Card>
                );
              }
              return (
                <Staking
                  network={network}
                  isHardware={isHardware}
                  walletId={walletId}
                  poolId={poolId}
                  setPoolId={setPoolId}
                  startInCompose={composeIntent}
                  onComposeStarted={() => setComposeIntent(false)}
                />
              );
            case "rewards":
              return <RewardHistory network={network} />;
            case "pools":
              // No delegate action for a wallet that cannot delegate: the
              // button would hand the pool to a tab that only explains why it
              // is unavailable, silently dropping the choice.
              return (
                <PoolDirectory
                  network={network}
                  onDelegate={canDelegate ? handleDelegate : undefined}
                />
              );
          }
        }}
      </Tabs>
    </div>
  );
}
