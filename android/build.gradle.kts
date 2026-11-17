plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.2.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.21" apply false
}

// Optional out-of-tree Gradle build directory (set VELOX_BUILD_DIR to relocate build outputs)
System.getenv("VELOX_BUILD_DIR")?.takeIf { it.isNotBlank() }?.let { extBuild ->
    layout.buildDirectory.set(file("$extBuild/root"))
    subprojects {
        layout.buildDirectory.set(file("$extBuild/${project.name}"))
    }
}
