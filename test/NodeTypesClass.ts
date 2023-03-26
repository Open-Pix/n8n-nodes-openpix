import { ManualTrigger } from 'n8n-nodes-base/dist/nodes/ManualTrigger/ManualTrigger.node';
import {
  INodeType,
  INodeTypeData,
  INodeTypes,
  IVersionedNodeType,
  NodeHelpers,
} from 'n8n-workflow';
import { OpenPix } from '../nodes/OpenPix/OpenPix.node';
import { OpenPixTrigger } from '../nodes/OpenPix/OpenPixTrigger.node';

export class NodeTypesClass implements INodeTypes {
  nodeTypes: INodeTypeData = {};
  getByName(nodeType: string): INodeType | IVersionedNodeType {
    return this.nodeTypes[nodeType].type;
  }

  addNode(nodeTypeName: string, nodeType: INodeType | IVersionedNodeType) {
    const loadedNode = {
      [nodeTypeName]: {
        sourcePath: '',
        type: nodeType,
      },
    };

    this.nodeTypes = {
      ...this.nodeTypes,
      ...loadedNode,
    };

    Object.assign(this.nodeTypes, loadedNode);
  }

  getByNameAndVersion(nodeType: string, version?: number): INodeType {
    return NodeHelpers.getVersionedNodeType(
      this.nodeTypes[nodeType].type,
      version,
    );
  }
}

const nodeTypes = new NodeTypesClass();

nodeTypes.addNode('n8n-nodes-base.manualTrigger', new ManualTrigger());
nodeTypes.addNode('n8n-nodes-openpix.openpix', new OpenPix());
nodeTypes.addNode('n8n-nodes-openpix.openpixTrigger', new OpenPixTrigger());

export { nodeTypes };
