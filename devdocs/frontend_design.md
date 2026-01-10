# Frontend Web Design for IDA Project MCP

## 1. Overview
The goal is to design a modern, web-based frontend for the IDA Project MCP system. This frontend will consume the REST APIs provided by the `mcp-http-server` to allow users to browse, search, and analyze reverse engineering artifacts (binaries, functions, disassembly, pseudocode, etc.) exported from IDA Pro.

## 2. Architecture & Tech Stack

### 2.1 Technology Choices
- **Framework**: React 18+ (SPA) using Vite for build tooling.
- **Language**: TypeScript for type safety, matching the structured data from the backend.
- **State Management**: React Query (TanStack Query) for server state caching and pagination handling; Context API for global UI state (theme, sidebar toggle).
- **Routing**: React Router v6.
- **Styling**: Tailwind CSS for utility-first styling.
- **UI Components**: Shadcn UI (or similar Headless UI wrapper) for accessible, customizable components (Tables, Dialogs, Dropdowns).
- **Code/Text Viewing**: Monaco Editor (read-only) for Pseudocode/Disassembly highlighting.
- **HTTP Client**: Axios.

### 2.2 Directory Structure
```
frontend/
├── src/
│   ├── api/            # API client and type definitions
│   ├── components/     # Reusable UI components (HexView, DataTable, etc.)
│   ├── pages/          # Main page views
│   │   ├── Dashboard/
│   │   ├── BinaryOverview/
│   │   └── FunctionDetail/
│   ├── layouts/        # MainLayout, BinaryLayout
│   ├── hooks/          # Custom hooks (useBinary, useFunction)
│   └── utils/          # Formatting helpers (address formatting)
```

## 3. API Integration Strategy
The frontend will communicate with the backend at `/api/v1`.

- **Base URL**: Configurable (default: `http://localhost:8765/api/v1`)
- **Error Handling**: Global interceptor for 404 (Not Found) and 500 (Server Error).
- **Pagination**: All list endpoints (`list_binary_functions`, `list_binary_strings`, etc.) support `offset` and `limit`. The frontend `DataTable` component will handle server-side pagination.
- **Search**: Search inputs will debounce and trigger API calls with the `query` parameter.

## 4. UI/UX Design

### 4.1 Sitemap
1.  **Home / Dashboard** (`/`)
    - List of available binaries in the project.
    - Project statistics.
2.  **Binary Workspace** (`/binary/:binaryName`)
    - **Overview** (`/overview`): Metadata, Sections, Segments.
    - **Functions** (`/functions`): Searchable list of functions.
    - **Strings** (`/strings`): Searchable list of strings.
    - **Imports/Exports** (`/imports`, `/exports`): Dependency lists.
    - **Symbols** (`/symbols`): Global symbol table.
3.  **Analysis View** (`/binary/:binaryName/function/:address`)
    - Split view: Disassembly / Pseudocode.
    - Side panels: Xrefs, Callers, Callees.

### 4.2 Page Layouts

#### A. Main Layout (Dashboard)
- **Header**: Logo, Global Search (optional), Theme Toggle.
- **Content**: Card grid of binaries.

#### B. Binary Layout
- **Sidebar**:
    - **Context**: Current Binary Name.
    - **Navigation**: Overview, Functions, Strings, Imports, Exports, Symbols.
- **Main Area**: Displays the selected list or detail view.

## 5. Detailed Features

### 5.1 Project Dashboard
- **Goal**: Select a binary to analyze.
- **API**: `GET /project/binaries`
- **UI**:
    - Card view showing Binary Name, Architecture, File Size, Function Count.

### 5.2 Function Browser
- **Goal**: Find specific functions.
- **API**: `GET /binary/{name}/functions`
- **UI**:
    - **Search Bar**: Filter by name.
    - **Table Columns**: Address (Hex), Name, Size, Stack Size.
    - **Action**: Click row to navigate to **Analysis View**.

### 5.3 String/Symbol Browser
- **Goal**: Find interesting data references.
- **API**: `GET /binary/{name}/strings`, `GET /binary/{name}/symbols`
- **UI**:
    - Virtualized table for performance.
    - Filter by string content or minimum length.
    - **Cross-Reference**: Clicking an address should show Xrefs (if implemented via `resolve_address` or similar).

### 5.4 Analysis View (The Core)
- **Goal**: Deep dive into code.
- **URL**: `/binary/:name/function/:address`
- **Layout**:
    - **Top Bar**: Function Name, Address, basic stats (size).
    - **Left Panel (Disassembly)**:
        - API: `GET /binary/{name}/function/{address}/disassembly`
        - Display: Linear disassembly with syntax highlighting.
        - Interaction: Click operands to navigate.
    - **Right Panel (Pseudocode)**:
        - API: `GET /binary/{name}/function/{address}/pseudocode`
        - Display: C-like code in Monaco Editor.
        - Toggle: Show/Hide.
    - **Bottom/Side Panel (Relationships)**:
        - Tabs: **Callers**, **Callees**, **Xrefs**.
        - API: `/callers`, `/callees`, `/xrefs/to`, `/xrefs/from`.
        - List of addresses/names that link to the current function.

### 5.5 Hex View (Modal/Panel)
- **Goal**: Inspect raw bytes.
- **API**: `GET /binary/{name}/bytes`
- **UI**: Typical Hex editor layout (Offset | Hex Bytes | ASCII).
- **Input**: Address and Length.

## 6. Development Plan
1.  **Phase 1**: Setup React project, API client, and Dashboard (Project/Binary list).
2.  **Phase 2**: Implement "Browser" views (Functions, Strings, Imports/Exports) with pagination.
3.  **Phase 3**: Implement Analysis View (Disassembly & Pseudocode rendering).
4.  **Phase 4**: Implement Navigation (Xrefs, clicking addresses to jump).

## 7. Questions/Confirmations
- Should the frontend support multiple projects, or is one server instance tied to one project? (Current assumption: Single project per server instance).
- Is "Graph View" (Control Flow Graph) a priority? (Not in initial scope, linear disassembly first).
