$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\dependencies\Get-ResolvedNuGetGraph.ps1')

Describe 'Get-ResolvedNuGetGraph' {
    It 'returns only normalized resolved package identities' {
        $path = Join-Path $repositoryRoot 'tests\fixtures\nuget\project.assets.json'
        $graph = @(Get-ResolvedNuGetGraph -LiteralPath $path)

        $graph.Count | Should Be 2
        $graph[0].id | Should Be 'another.package'
        $graph[1].version | Should Be '2.0.0'
    }

    It 'fails closed when the graph is missing' {
        $threw = $false
        try { Get-ResolvedNuGetGraph -LiteralPath (Join-Path $TestDrive 'missing.json') | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}
