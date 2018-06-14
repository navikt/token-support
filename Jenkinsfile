@Library('deploy')
import deploy

def deployLib = new deploy()

node {
    def commitHash, commitHashShort, commitUrl
    def repo = "navikt"
    def app = "token-support"
    def committer, committerEmail, changelog, releaseVersion
    def mvnHome = tool "maven-3.3.9"
    def mvn = "${mvnHome}/bin/mvn"
   

    stage("Initialization") {
        cleanWs()
        withCredentials([string(credentialsId: 'OAUTH_TOKEN', variable: 'token')]) {
           withEnv(['HTTPS_PROXY=http://webproxy-utvikler.nav.no:8088']) {
            sh(script: "git clone https://${token}:x-oauth-basic@github.com/${repo}/${app}.git .")
           }
         }
        commitHash = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
        commitHashShort = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
        commitUrl = "https://github.com/${repo}/${app}/commit/${commitHash}"
        committer = sh(script: 'git log -1 --pretty=format:"%an"', returnStdout: true).trim()
        committerEmail = sh(script: 'git log -1 --pretty=format:"%ae"', returnStdout: true).trim()
        changelog = sh(script: 'git log `git describe --tags --abbrev=0`..HEAD --oneline', returnStdout: true)
    }

    stage("Build & Deploy Snapshot") {
        sh "mkdir -p /tmp/${app}"   
		def pom = readMavenPom file: 'pom.xml'
		
		script {
			if (pom.version.contains('SNAPSHOT')) {
				sh "${mvn} clean deploy -Djava.io.tmpdir=/tmp/${app} -B -e"
			} else {
				sh "${mvn} clean install -Djava.io.tmpdir=/tmp/${app} -B -e"
			}
		}
    }
}