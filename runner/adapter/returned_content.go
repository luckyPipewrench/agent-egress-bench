package adapter

import (
	"bytes"
	"encoding/json"
	"mime"
	"strings"
)

func returnedContent(bytes []byte, mediaType, path string) ReturnedContent {
	copied := append([]byte(nil), bytes...)
	observation := ReturnedContent{Bytes: copied, MediaType: boundedMediaType(mediaType), Path: path}
	if metadata := returnedContentMetadata(bytes); len(metadata) > 0 {
		observation.Metadata = metadata
	}
	return observation
}

func returnedContentMetadata(body []byte) map[string]interface{} {
	if metadata := returnedContentJSONMetadata(body); len(metadata) > 0 {
		return metadata
	}

	var dataLines [][]byte
	for _, rawLine := range bytes.Split(body, []byte("\n")) {
		line := bytes.TrimSuffix(rawLine, []byte("\r"))
		if len(line) == 0 {
			if metadata := returnedContentJSONMetadata(bytes.Join(dataLines, []byte("\n"))); len(metadata) > 0 {
				return metadata
			}
			dataLines = nil
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			data := line[len("data:"):]
			if len(data) > 0 && data[0] == ' ' {
				data = data[1:]
			}
			dataLines = append(dataLines, data)
		}
	}
	return returnedContentJSONMetadata(bytes.Join(dataLines, []byte("\n")))
}

func returnedContentJSONMetadata(body []byte) map[string]interface{} {
	var response struct {
		Result struct {
			Tools        []json.RawMessage `json:"tools"`
			Instructions *json.RawMessage  `json:"instructions"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &response) != nil {
		return nil
	}
	metadata := map[string]interface{}{}
	if len(response.Result.Tools) > 0 {
		metadata["returned_content_tool_count"] = len(response.Result.Tools)
		for _, tool := range response.Result.Tools {
			var shape map[string]json.RawMessage
			if json.Unmarshal(tool, &shape) != nil {
				continue
			}
			for _, key := range []string{"title", "inputSchema", "outputSchema", "annotations"} {
				if _, ok := shape[key]; ok {
					metadata["returned_content_has_"+strings.ToLower(key)] = true
				}
			}
		}
	}
	if response.Result.Instructions != nil {
		metadata["returned_content_has_instructions"] = true
	}
	return metadata
}

func boundedMediaType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		return "application/octet-stream"
	}
	switch mediaType {
	case "application/json", "text/event-stream", "application/octet-stream", "text/plain":
		return mediaType
	default:
		return "application/octet-stream"
	}
}
