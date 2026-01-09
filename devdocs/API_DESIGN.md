# Web Design & REST API Specification

## 1. Web Application Design Concept

The proposed frontend is a Single Page Application (SPA) designed for reverse engineering analysis and project exploration.

### Core Modules:

1.  **Project Dashboard**
    *   Displays project overview (Project Name, Backend Type, Analysis Status).
    *   Lists all binaries associated with the project.
    *   Provides search/filter capabilities for binaries.

2.  **Binary Analysis View**
    *   **Navigation/Sidebar**:
        *   **Functions**: List of functions with search/filter (Name, Address, Size).
        *   **Symbols**: List of symbols.
        *   **Imports/Exports**: External dependencies and exposed interfaces.
        *   **Strings**: List of strings found in the binary.
        *   **Sections/Segments**: Memory layout information.
    *   **Main Workspace (Tabs/Panels)**:
        *   **Disassembly View**: Linear disassembly view.
        *   **Pseudocode View**: High-level decompiled code (if available).
        *   **Hex/Byte View**: Raw memory viewer.
    *   **Context/Detail Panel**:
        *   **Cross References (XRefs)**: Callers, Callees, Data refs.
        *   **Address Info**: Details about the currently selected address.

## 2. REST API Specification

All API endpoints are prefixed with `/api/v1`.

### Project Endpoints

#### Get Project Overview
*   **GET** `/api/v1/project`
*   **Description**: Returns high-level project information.
*   **Response**:
    ```json
    {
      "project": "project_id",
      "binaries_count": 5,
      "analysis_status": "ready",
      "capabilities": { ... }
    }
    ```

#### List Binaries
*   **GET** `/api/v1/project/binaries`
*   **Query Params**:
    *   `offset` (int, default: 0)
    *   `limit` (int, default: 50)
*   **Response**: List of binary summaries.

### Binary Information Endpoints

#### Get Binary Metadata
*   **GET** `/api/v1/binary/{binary_name}`
*   **Response**: Architecture, file type, hash, etc.

#### List Sections
*   **GET** `/api/v1/binary/{binary_name}/sections`
*   **Response**: List of sections (name, start, size).

#### List Segments
*   **GET** `/api/v1/binary/{binary_name}/segments`
*   **Response**: List of segments (name, start, size, perms).

### Code & Data Listings

#### List Functions
*   **GET** `/api/v1/binary/{binary_name}/functions`
*   **Query Params**:
    *   `query` (string, optional): Search by name.
    *   `offset` (int, default: 0)
    *   `limit` (int, default: 50)
*   **Response**: List of functions.

#### List Imports
*   **GET** `/api/v1/binary/{binary_name}/imports`
*   **Query Params**: `offset`, `limit`

#### List Exports
*   **GET** `/api/v1/binary/{binary_name}/exports`
*   **Query Params**: `offset`, `limit`

#### List Symbols
*   **GET** `/api/v1/binary/{binary_name}/symbols`
*   **Query Params**: `query`, `offset`, `limit`

#### List Strings
*   **GET** `/api/v1/binary/{binary_name}/strings`
*   **Query Params**: `query`, `min_length`, `offset`, `limit`

### Analysis & Content Endpoints

#### Get Disassembly
*   **GET** `/api/v1/binary/{binary_name}/disassembly`
*   **Query Params**:
    *   `start_address` (required): Hex or Int.
    *   `end_address` (required): Hex or Int.
*   **Response**: Text content.

#### Get Function Disassembly
*   **GET** `/api/v1/binary/{binary_name}/function/{address}/disassembly`
*   **Response**: Text content.

#### Get Function Pseudocode
*   **GET** `/api/v1/binary/{binary_name}/function/{address}/pseudocode`
*   **Response**: Decompiled code structure.

#### Get Raw Bytes
*   **GET** `/api/v1/binary/{binary_name}/bytes`
*   **Query Params**:
    *   `address` (required)
    *   `length` (required, int)
*   **Response**: Hex encoded string or requested format.

#### Resolve Address
*   **GET** `/api/v1/binary/{binary_name}/address/{address}`
*   **Response**: Information about what exists at the given address.

### Cross References

#### Get Callers
*   **GET** `/api/v1/binary/{binary_name}/function/{address}/callers`

#### Get Callees
*   **GET** `/api/v1/binary/{binary_name}/function/{address}/callees`

#### Get XRefs To Address
*   **GET** `/api/v1/binary/{binary_name}/xrefs/to/{address}`

#### Get XRefs From Address
*   **GET** `/api/v1/binary/{binary_name}/xrefs/from/{address}`

