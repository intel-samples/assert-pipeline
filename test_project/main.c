#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX 1024
#define BASE_DIR "/srv/cmdbox/data/"

struct node {
    int   tag;
    char *label;
};

static struct node *g_handle = NULL;

static void cmd_say(const char *text) {
    printf(text);
    printf("\n");
}

static void cmd_stash(const char *text) {
    char slot[32];
    strcpy(slot, text);
    printf("stashed: %s\n", slot);
}

static void cmd_grow(const char *count_str, const char *byte_str) {
    unsigned int count = (unsigned int)strtoul(count_str, NULL, 10);
    unsigned char fill = (unsigned char)strtoul(byte_str, NULL, 10);

    unsigned char *buf = malloc(count * sizeof(unsigned int));
    if (!buf) return;

    for (unsigned int i = 0; i < count * sizeof(unsigned int); i++) {
        buf[i] = fill;
    }
    printf("grew %u bytes\n", count * (unsigned int)sizeof(unsigned int));
    free(buf);
}

static void cmd_shell(const char *arg) {
    char command[256];
    snprintf(command, sizeof(command), "echo running: %s", arg);
    system(command);
}

static void cmd_open(const char *relpath) {
    char path[256];
    snprintf(path, sizeof(path), "%s%s", BASE_DIR, relpath);

    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return; }

    char chunk[128];
    size_t r = fread(chunk, 1, sizeof(chunk) - 1, f);
    chunk[r] = '\0';
    printf("%s", chunk);
    fclose(f);
}

static void cmd_pick(const char *index_str) {
    static const int table[4] = { 10, 20, 30, 40 };
    int idx = atoi(index_str);
    printf("value[%d] = %d\n", idx, table[idx]);
}

static void cmd_make(void) {
    g_handle = malloc(sizeof(struct node));
    if (!g_handle) return;
    g_handle->tag = 1;
    g_handle->label = strdup("node");
    printf("made node\n");
}

static void cmd_drop(void) {
    if (!g_handle) return;
    free(g_handle->label);
    free(g_handle);

    printf("dropped node\n");
}

static void cmd_touch(void) {
    if (!g_handle) { printf("no node\n"); return; }
    g_handle->tag++;
    printf("touched node, tag=%d label=%s\n", g_handle->tag, g_handle->label);
}

static void dispatch(char *line) {
    char *cmd = strtok(line, " \t\r\n");
    if (!cmd) return;

    if (strcmp(cmd, "say") == 0) {
        char *rest = strtok(NULL, "\r\n");
        cmd_say(rest ? rest : "");
    } else if (strcmp(cmd, "stash") == 0) {
        char *rest = strtok(NULL, "\r\n");
        cmd_stash(rest ? rest : "");
    } else if (strcmp(cmd, "grow") == 0) {
        char *a = strtok(NULL, " \t\r\n");
        char *b = strtok(NULL, " \t\r\n");
        cmd_grow(a ? a : "0", b ? b : "0");
    } else if (strcmp(cmd, "shell") == 0) {
        char *rest = strtok(NULL, "\r\n");
        cmd_shell(rest ? rest : "");
    } else if (strcmp(cmd, "open") == 0) {
        char *rest = strtok(NULL, " \t\r\n");
        cmd_open(rest ? rest : "");
    } else if (strcmp(cmd, "pick") == 0) {
        char *rest = strtok(NULL, " \t\r\n");
        cmd_pick(rest ? rest : "0");
    } else if (strcmp(cmd, "make") == 0) {
        cmd_make();
    } else if (strcmp(cmd, "drop") == 0) {
        cmd_drop();
    } else if (strcmp(cmd, "touch") == 0) {
        cmd_touch();
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <script-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("fopen"); return 1; }

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), f)) {
        dispatch(line);
    }

    fclose(f);
    return 0;
}
