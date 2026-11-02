import { ConfirmAction } from "@/components/confirm-action";
import { Cell, EmptyState, PageHeader, Pagination, Panel, StatusBadge, Table } from "@/components/ui";
import { api, query } from "@/lib/api";
import { pageOffset } from "@/lib/format";
import type { Agent, Me, Page } from "@/lib/types";
import { setAgentStatus } from "./actions";

export const metadata = { title: "Agent Registry | AEGIS" };

export default async function AgentsPage({
  searchParams,
}: {
  searchParams: Promise<{ offset?: string }>;
}) {
  const { offset } = await searchParams;
  const [page, me] = await Promise.all([
    api<Page<Agent>>(`/agents${query({ offset: pageOffset(offset) })}`),
    api<Me>("/auth/me"),
  ]);
  const canManage = me.role === "admin";

  return (
    <>
      <PageHeader
        title="Agent Registry"
        description="Agent identities and what each may use. Access not listed here is denied."
      />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="No agents registered"
            detail="An administrator can register one with POST /api/v1/agents."
          />
        ) : (
          <Table
            head={[
              "Agent",
              "Owner",
              "Status",
              "Permitted tools",
              "Resources",
              "Active credentials",
              ...(canManage ? ["Actions"] : []),
            ]}
          >
            {page.items.map((agent) => {
              const disabling = agent.status === "active";
              return (
                <tr key={agent.id}>
                  <Cell>{agent.name}</Cell>
                  <Cell>{agent.owner}</Cell>
                  <Cell>
                    <StatusBadge value={agent.status} />
                  </Cell>
                  <Cell mono>
                    {agent.tool_grants.length > 0 ? agent.tool_grants.join(", ") : "None"}
                  </Cell>
                  <Cell>{agent.resource_grants.length}</Cell>
                  <Cell>
                    {agent.credentials.filter((credential) => !credential.revoked_at).length}
                  </Cell>
                  {canManage && (
                    <Cell>
                      <ConfirmAction
                        trigger={disabling ? "Disable" : "Enable"}
                        triggerLabel={disabling ? `Disable ${agent.name}` : `Enable ${agent.name}`}
                        title={disabling ? `Disable ${agent.name}?` : `Enable ${agent.name}?`}
                        confirmLabel={disabling ? "Disable agent" : "Enable agent"}
                        danger={disabling}
                        action={setAgentStatus}
                        fields={{
                          agent_id: agent.id,
                          status: disabling ? "disabled" : "active",
                        }}
                      >
                        {disabling
                          ? "Every action this agent submits will be denied, including actions that were already approved but have not run. This is recorded in the audit log."
                          : "This agent's existing permissions will apply again. This is recorded in the audit log."}
                      </ConfirmAction>
                    </Cell>
                  )}
                </tr>
              );
            })}
          </Table>
        )}
        <Pagination basePath="/agents" {...page} />
      </Panel>
    </>
  );
}
