public enum ProcessType {
    ENCRYPTION("0"),
    DECRYPTION("1");
    public final String label;
    ProcessType(String label) {
        this.label = label;
    }
}
