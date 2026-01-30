package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// extractHostAgentName parses nftData string like "{'agent_name': 'mike'}" to extract agent_name.
func extractHostAgentName(nftData string) string {
	// Convert Python-style single quotes to JSON double quotes
	normalized := strings.ReplaceAll(nftData, "'", "\"")

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &obj); err != nil {
		return ""
	}

	agentName, ok := obj["agent_name"].(string)
	if !ok {
		return ""
	}
	return agentName
}

type remoteInfo struct {
	Name string `json:"name"`
	Did  string `json:"did"`
}

func extractRemoteInfo(payload nftPayload) ([]*remoteInfo, error) {
	normalized := strings.ReplaceAll(payload.NFTData, "'", "\"")

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &obj); err != nil {
		return nil, fmt.Errorf("extractRemoteInfo: failed to unmarshall nft data, err: %v", err)
	}

	if _, ok := obj["responses"]; !ok {
		return nil, fmt.Errorf("extractRemoteInfo: 'response' attribute doesn't exists")
	}

	remote_reponses, ok := obj["responses"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("extractRemoteInfo: unable to type infer `responses` attribute")
	}

	var remoteInfoList []*remoteInfo = make([]*remoteInfo, 0)

	for _, response := range remote_reponses {
		responseObj, ok := response.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("extractRemoteInfo: unable to type infer `response` attribute")
		}

		if _, ok := responseObj["agent"]; !ok {
			return nil, fmt.Errorf("extractRemoteInfo: `agent` attribute is not found within 'response' attribute")
		}

		agentName, ok := responseObj["agent"].(string)
		if !ok {
			return nil, fmt.Errorf("extractRemoteInfo: `agent` attribute is not of type string.")
		}

		if _, ok := responseObj["agent_did"]; !ok {
			remoteInfoList = append(remoteInfoList, &remoteInfo{
				Name: agentName,
				Did:  agentName,
			})
			continue
		}

		agentDid, ok := responseObj["agent_did"].(string)
		if !ok {
			return nil, fmt.Errorf("extractRemoteInfo: 'agent_did' attribute is not type string")
		}

		remoteInfoList = append(remoteInfoList, &remoteInfo{
			Name: agentName,
			Did:  agentDid,
		})
	}

	return remoteInfoList, nil
}

func extractAgentInteractions(payload nftPayload, db *sql.DB) ([]*agentInteraction, error) {
	var interactionList []*agentInteraction = make([]*agentInteraction, 0)

	agentID := payload.NFT
	epoch := time.Now().Unix()

	normalized := strings.ReplaceAll(payload.NFTData, "'", "\"")
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &obj); err != nil {
		return nil, fmt.Errorf("extractAgentInteractions: failed to unmarshall nft data, err: %v", err)
	}

	hostObj, ok := obj["host"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `host` attribute")
	}

	agentDID, ok := hostObj["agent"].(string)
	if !ok {
		return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `host.agent` attribute")
	}

	verifictionObj, ok := obj["verification"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `verification` attribute")
	}

	trustIssues, ok := verifictionObj["trust_issues"].([]string)
	if !ok {
		return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `trust_issues` attribute")		
	}

	responses, ok := obj["responses"].([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `responses` attribute")
	}

	rows, err := db.Query("SELECT nft_name FROM nfts WHERE nft_id = ?", agentID)
	if err != nil {
		return nil, fmt.Errorf("extractAgentInteractions: failed to query nft name, err: %v", err)
	}
	defer rows.Close()

	var agentName string
	if rows.Next() {
		if err := rows.Scan(&agentName); err != nil {
			return nil, fmt.Errorf("extractAgentInteractions: failed to scan nft name, err: %v", err)
		}
	}

	for idx, response := range responses {
		remoteName, ok := response["agent"].(string)
		if !ok {
			return nil, fmt.Errorf("extractAgentInteractions: unable to type infer `agent` attribute in response")
		}

		remoteDID, ok := response["agent_did"].(string)
		if !ok {
			remoteDID = remoteName
		}


		var trustIssueStr string = ""
		
		if len(trustIssues) > 0 {
			if idx >= len(trustIssues) {
				return nil, fmt.Errorf("extractAgentInteractions: response index out of range")
			}

			trustIssueStr = trustIssues[idx]
		}

		interactionList = append(interactionList, &agentInteraction{
			HostID: agentID,
			HostDID: agentDID,
			HostName: agentName,
			RemoteName: remoteName,
			RemoteDID:  remoteDID,
			Epoch: epoch,
			IntrusionCause: trustIssueStr,
		})
	}

	return interactionList, nil
}
